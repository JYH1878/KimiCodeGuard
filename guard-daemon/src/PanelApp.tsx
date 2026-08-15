// 审计面板主组件（M6）：统计卡 + 近 14 天柱状条 + 高频工具 Top5 + 可筛选事件流。
// 数据全部来自三个只读 tauri 命令（panel_query / panel_stats / panel_row）；
// 自动刷新开时监听 daemon 推来的 audit-event：首页重查、统计卡重拉，关时不监听。
import { Fragment, useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";

const PAGE_SIZE = 100;
const DAYS = 14;

interface PanelEventRow {
  id: number;
  ts: number;
  event: string;
  session_id: string;
  cwd: string;
  tool_name: string | null;
  decision: string | null;
  reason: string | null;
  payload: string;
  payload_truncated: boolean;
}

interface QueryPage {
  rows: PanelEventRow[];
  total: number;
}

interface DecisionCounts {
  deny: number;
  ask_allow: number;
  ask_deny: number;
  allow: number;
}

interface NameCount {
  name: string;
  count: number;
}

interface PanelStats {
  today: DecisionCounts;
  total: DecisionCounts;
  total_rows: number;
  events: NameCount[];
  tools: NameCount[];
  daily: number[];
}

// daemon 侧 emit 的实时事件摘要（payload 全文由展开时调 panel_row 取）
interface AuditEventSummary {
  id: number;
  ts: number;
  event: string;
  session_id: string;
  cwd: string;
  tool_name: string | null;
  decision: string | null;
  reason: string | null;
}

interface Filters {
  decision: string;
  event: string;
  keyword: string;
}

const EMPTY_FILTERS: Filters = { decision: "", event: "", keyword: "" };

/** 本地午夜（Unix 毫秒）——「今日 / 每日」边界由前端算好传后端，Rust 不碰时区 */
function localMidnight(date: Date): number {
  return new Date(date.getFullYear(), date.getMonth(), date.getDate()).getTime();
}

/** 近 DAYS 天每日起点（升序，最后一项 = 今日） */
function dayStarts(): number[] {
  const today = localMidnight(new Date());
  const starts: number[] = [];
  for (let i = DAYS - 1; i >= 0; i--) {
    starts.push(today - i * 86_400_000);
  }
  return starts;
}

function fmtTime(ts: number): string {
  const d = new Date(ts);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(
    d.getHours()
  )}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

export default function PanelApp() {
  const { t } = useTranslation();

  // —— 数据态 ——
  const [stats, setStats] = useState<PanelStats | null>(null);
  const [dayBounds, setDayBounds] = useState<number[]>(() => dayStarts());
  const [rows, setRows] = useState<PanelEventRow[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [cursorStack, setCursorStack] = useState<number[]>([]);
  const [loading, setLoading] = useState(false);
  const [dbError, setDbError] = useState<string | null>(null);

  // —— 筛选态（输入控件值；已生效的筛选在 filtersRef）——
  const [decisionInput, setDecisionInput] = useState("");
  const [eventInput, setEventInput] = useState("");
  const [keywordInput, setKeywordInput] = useState("");
  const [autoRefresh, setAutoRefresh] = useState(true);

  // —— 详情展开态 ——
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [detail, setDetail] = useState<PanelEventRow | null>(null);

  const filtersRef = useRef<Filters>(EMPTY_FILTERS);
  const pageRef = useRef(0);
  useEffect(() => {
    pageRef.current = page;
  }, [page]);

  const loadStats = useCallback(async () => {
    try {
      // 边界每次现算：面板跨天开着时「今日」跟着本地午夜走（模块常量会在跨天后失真）
      const bounds = dayStarts();
      setDayBounds(bounds);
      const s = await invoke<PanelStats>("panel_stats", {
        todayStartTs: bounds[bounds.length - 1],
        dayStartsTs: bounds,
      });
      setStats(s);
      setDbError(null);
    } catch (e) {
      setDbError(String(e));
    }
  }, []);

  const loadPage = useCallback(
    async (f: Filters, cursor: number | undefined, pageNo: number, silent: boolean) => {
      if (!silent) setLoading(true);
      try {
        const result = await invoke<QueryPage>("panel_query", {
          filter: {
            event: f.event || null,
            decision: f.decision || null,
            toolName: null,
            keyword: f.keyword || null,
            tsFrom: null,
            tsTo: null,
            cursor: cursor ?? null,
          },
          limit: PAGE_SIZE,
        });
        setRows(result.rows);
        setTotal(result.total);
        setPage(pageNo);
        setDbError(null);
      } catch (e) {
        setDbError(String(e));
        setRows([]);
        setTotal(0);
      } finally {
        if (!silent) setLoading(false);
      }
    },
    []
  );

  // 首次加载（StrictMode 双跑防护）
  const didInit = useRef(false);
  useEffect(() => {
    if (didInit.current) return;
    didInit.current = true;
    void loadStats();
    void loadPage(filtersRef.current, undefined, 0, false);
  }, [loadStats, loadPage]);

  // 自动刷新：开时监听 audit-event（首页重查 + 统计重拉），关时不监听
  useEffect(() => {
    if (!autoRefresh) return;
    let disposed = false;
    let unlistenFn: (() => void) | undefined;
    void listen<AuditEventSummary>("audit-event", () => {
      void loadStats();
      if (pageRef.current === 0) {
        void loadPage(filtersRef.current, undefined, 0, true);
      }
    }).then((fn) => {
      if (disposed) {
        fn();
      } else {
        unlistenFn = fn;
      }
    });
    return () => {
      disposed = true;
      unlistenFn?.();
    };
  }, [autoRefresh, loadStats, loadPage]);

  // —— 交互 ——
  const applyQuery = () => {
    const f: Filters = {
      decision: decisionInput,
      event: eventInput,
      keyword: keywordInput.trim(),
    };
    filtersRef.current = f;
    setCursorStack([]);
    void loadPage(f, undefined, 0, false);
    void loadStats();
  };

  const goPrev = () => {
    if (page === 0) return;
    const prevStack = cursorStack.slice(0, -1);
    setCursorStack(prevStack);
    const cursor = prevStack.length > 0 ? prevStack[prevStack.length - 1] : undefined;
    void loadPage(filtersRef.current, cursor, page - 1, false);
  };

  const goNext = () => {
    if (rows.length === 0 || page * PAGE_SIZE + rows.length >= total) return;
    const lastId = rows[rows.length - 1].id;
    const nextStack = [...cursorStack, lastId];
    setCursorStack(nextStack);
    void loadPage(filtersRef.current, lastId, page + 1, false);
  };

  const toggleRow = (row: PanelEventRow) => {
    if (expandedId === row.id) {
      setExpandedId(null);
      setDetail(null);
      return;
    }
    setExpandedId(row.id);
    setDetail(null);
    void invoke<PanelEventRow | null>("panel_row", { id: row.id })
      .then(setDetail)
      .catch(() => setDetail(null));
  };

  // —— 渲染辅助 ——
  const decisionClass = (d: string | null): string => {
    if (d === "deny") return "decision-deny";
    if (d === "ask_allow" || d === "ask_deny") return "decision-ask";
    if (d === "allow") return "decision-allow";
    return "decision-none";
  };

  const decisionLabel = (d: string | null): string => {
    if (!d) return t("panel.decision.none");
    return t(`panel.decision.${d}`, { defaultValue: d });
  };

  const cardValue = (v: number | null): string => (v === null ? "…" : String(v));

  const today = stats?.today;
  const maxDaily = Math.max(...(stats?.daily ?? [1]), 1);

  return (
    <div className="panel-root">
      {dbError !== null && (
        <div className="panel-error">{t("panel.dbError", { error: dbError })}</div>
      )}

      <section className="panel-stats">
        <div className="panel-cards">
          <div className="panel-card">
            <span className="panel-card-value deny">
              {cardValue(today === undefined ? null : today.deny + today.ask_deny)}
            </span>
            <span className="panel-card-label">{t("panel.stats.todayDenied")}</span>
          </div>
          <div className="panel-card">
            <span className="panel-card-value ask">
              {cardValue(today === undefined ? null : today.ask_allow)}
            </span>
            <span className="panel-card-label">{t("panel.stats.todayAskAllowed")}</span>
          </div>
          <div className="panel-card">
            <span className="panel-card-value allow">
              {cardValue(today === undefined ? null : today.allow)}
            </span>
            <span className="panel-card-label">{t("panel.stats.todayAllowed")}</span>
          </div>
          <div className="panel-card">
            <span className="panel-card-value total">
              {cardValue(stats === null ? null : stats.total_rows)}
            </span>
            <span className="panel-card-label">{t("panel.stats.totalEvents")}</span>
          </div>
        </div>

        <div className="panel-charts">
          <div className="panel-chart">
            <p className="panel-chart-title">{t("panel.stats.weeklyTitle")}</p>
            <div className="panel-bars">
              {(stats?.daily ?? []).map((count, i) => (
                <div className="panel-bar-col" key={dayBounds[i]}>
                  <div
                    className="panel-bar"
                    style={{ height: `${(count / maxDaily) * 100}%` }}
                    title={String(count)}
                  />
                  <span className="panel-bar-label">
                    {i === DAYS - 1
                      ? t("panel.stats.weeklyToday")
                      : new Date(dayBounds[i]).getDate()}
                  </span>
                </div>
              ))}
              {stats === null && <span className="panel-muted">{t("panel.loading")}</span>}
            </div>
          </div>

          <div className="panel-chart">
            <p className="panel-chart-title">{t("panel.stats.topTools")}</p>
            <ul className="panel-tools">
              {(stats?.tools ?? []).slice(0, 5).map((tool) => (
                <li key={tool.name}>
                  <span className="panel-tool-name">{tool.name}</span>
                  <span className="panel-tool-count">{tool.count}</span>
                </li>
              ))}
              {stats !== null && stats.tools.length === 0 && (
                <li className="panel-muted">{t("panel.stats.noData")}</li>
              )}
            </ul>
          </div>
        </div>
      </section>

      <section className="panel-filters">
        <select
          className="panel-select"
          value={decisionInput}
          onChange={(e) => setDecisionInput(e.target.value)}
          aria-label={t("panel.filters.decision")}
        >
          <option value="">{t("panel.filters.all")}</option>
          <option value="deny">{t("panel.decision.deny")}</option>
          <option value="ask_allow">{t("panel.decision.ask_allow")}</option>
          <option value="ask_deny">{t("panel.decision.ask_deny")}</option>
          <option value="allow">{t("panel.decision.allow")}</option>
        </select>
        <select
          className="panel-select"
          value={eventInput}
          onChange={(e) => setEventInput(e.target.value)}
          aria-label={t("panel.filters.event")}
        >
          <option value="">{t("panel.filters.all")}</option>
          {(stats?.events ?? []).map((ev) => (
            <option key={ev.name} value={ev.name}>
              {ev.name}
            </option>
          ))}
        </select>
        <input
          className="panel-input"
          type="text"
          value={keywordInput}
          placeholder={t("panel.filters.keywordPlaceholder")}
          onChange={(e) => setKeywordInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") applyQuery();
          }}
        />
        <button className="panel-btn primary" onClick={applyQuery}>
          {t("panel.filters.query")}
        </button>
        <label className="panel-auto">
          <input
            type="checkbox"
            checked={autoRefresh}
            onChange={(e) => setAutoRefresh(e.target.checked)}
          />
          {t("panel.filters.autoRefresh")}
        </label>
      </section>

      <section className="panel-table-wrap">
        <div className="panel-table-scroll">
          <table className="panel-table">
            <thead>
              <tr>
                <th>{t("panel.table.time")}</th>
                <th>{t("panel.table.event")}</th>
                <th>{t("panel.table.tool")}</th>
                <th>{t("panel.table.decision")}</th>
                <th>{t("panel.table.reason")}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <Fragment key={row.id}>
                  <tr
                    className={expandedId === row.id ? "panel-row active" : "panel-row"}
                    onClick={() => void toggleRow(row)}
                  >
                    <td className="panel-mono">{fmtTime(row.ts)}</td>
                    <td>{row.event}</td>
                    <td className="panel-mono">{row.tool_name ?? "—"}</td>
                    <td className={decisionClass(row.decision)}>{decisionLabel(row.decision)}</td>
                    <td className="panel-reason">{row.reason ?? "—"}</td>
                  </tr>
                  {expandedId === row.id && (
                    <tr className="panel-detail-row">
                      <td colSpan={5}>
                        <div className="panel-detail-head">
                          {t("panel.table.detail")} · id={row.id} · session={row.session_id} ·{" "}
                          {row.cwd}
                        </div>
                        <pre className="panel-payload">
                          {detail !== null ? detail.payload : t("panel.loading")}
                        </pre>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
          {rows.length === 0 && !loading && (
            <div className="panel-empty">{t("panel.empty")}</div>
          )}
          {loading && <div className="panel-loading">{t("panel.loading")}</div>}
        </div>
        <div className="panel-pagination">
          <button className="panel-btn" onClick={goPrev} disabled={page === 0 || loading}>
            {t("panel.pagination.prev")}
          </button>
          <span className="panel-page">{t("panel.pagination.page", { page: page + 1 })}</span>
          <button
            className="panel-btn"
            onClick={goNext}
            disabled={loading || rows.length === 0 || page * PAGE_SIZE + rows.length >= total}
          >
            {t("panel.pagination.next")}
          </button>
          <span className="panel-total">{t("panel.pagination.total", { count: total })}</span>
        </div>
      </section>
    </div>
  );
}
