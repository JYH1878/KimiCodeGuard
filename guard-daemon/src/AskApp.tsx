// ask 弹窗主组件：规则中文说明 + 工具名 + 完整命令 + 55s 倒计时进度条 + 允许/拒绝
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";

interface AskRequest {
  rule: string;
  tool: string;
  command: string;
  session_id: string;
}

// 与后端 ask 超时一致（src-tauri/src/daemon.rs ASK_TIMEOUT_DEFAULT = 55s）
const COUNTDOWN_SECONDS = 55;
const COUNTDOWN_MS = COUNTDOWN_SECONDS * 1000;

export default function AskApp() {
  const { t } = useTranslation();
  const [request, setRequest] = useState<AskRequest | null>(null);
  const [deadline, setDeadline] = useState(0);
  const [remainingMs, setRemainingMs] = useState(COUNTDOWN_MS);
  const [responded, setResponded] = useState(false);

  // 常驻监听：窗口隐藏时也在挂，请求一到立刻重置状态（新一单）
  useEffect(() => {
    const unlisten = listen<AskRequest>("ask-request", (event) => {
      setRequest(event.payload);
      setDeadline(Date.now() + COUNTDOWN_MS);
      setRemainingMs(COUNTDOWN_MS);
      setResponded(false);
    });
    return () => {
      void unlisten.then((f) => f());
    };
  }, []);

  // 倒计时（显示用；真正的超时裁决在后端 worker，前端挂了也不影响 fail-safe）
  useEffect(() => {
    if (!request) return;
    const timer = setInterval(() => {
      setRemainingMs(Math.max(0, deadline - Date.now()));
    }, 200);
    return () => clearInterval(timer);
  }, [request, deadline]);

  const expired = request !== null && remainingMs <= 0;

  const respond = (decision: "allow" | "deny") => {
    if (responded || expired) return;
    setResponded(true);
    void invoke("ask_respond", { decision });
  };

  if (!request) {
    return (
      <div className="ask-root">
        <p className="waiting">{t("ask.waiting")}</p>
      </div>
    );
  }

  const secondsLeft = Math.ceil(remainingMs / 1000);
  const pct = (remainingMs / COUNTDOWN_MS) * 100;

  return (
    <div className="ask-root">
      <header className="ask-header">
        <h1>{t("ask.title")}</h1>
        <p className="subtitle">{t("ask.subtitle")}</p>
      </header>

      <section className="ask-body">
        <p className="rule">
          {t(`ask.rule.${request.rule}`, { defaultValue: t("ask.ruleUnknown") })}
          <span className="rule-id">{request.rule}</span>
        </p>
        <p className="tool">
          <span className="label">{t("ask.toolLabel")}</span>
          <span className="tool-name">{request.tool}</span>
        </p>
        <p className="label">{t("ask.commandLabel")}</p>
        <pre className="command">{request.command}</pre>
      </section>

      <div className="countdown">
        <div className="countdown-bar">
          <div
            className={`countdown-fill${secondsLeft <= 10 ? " urgent" : ""}`}
            style={{ width: `${pct}%` }}
          />
        </div>
        <p className="countdown-text">
          {expired ? t("ask.expired") : t("ask.countdown", { seconds: secondsLeft })}
        </p>
      </div>

      <footer className="ask-actions">
        <button
          className="btn btn-deny"
          onClick={() => respond("deny")}
          disabled={responded || expired}
        >
          {t("ask.deny")}
        </button>
        <button
          className="btn btn-allow"
          onClick={() => respond("allow")}
          disabled={responded || expired}
        >
          {t("ask.allow")}
        </button>
      </footer>
    </div>
  );
}
