//! 活跃会话跟踪（M3 任务 4：daemon 随会话启停的核心判定）。
//!
//! 规则（GOAL.md 设计定案）：
//! - SessionStart 加、SessionEnd 删、SessionHeartbeat 刷新（其余事件 = 活跃证据，同样刷新）；
//!   对 daemon 重启后错过 Start 的会话，Heartbeat/PreToolUse 做补记（upsert）。
//! - 集合为空持续 idle_timeout（生产 5 分钟）→ `should_exit` 返回 true（空载自退）。
//! - 会话 24h（zombie_after）无任何事件 → 僵死清除（崩溃/kill 的会话不发 SessionEnd，必须兜底）。
//! - session_id 为空串的事件不参与跟踪（解析降级产物，免得把 daemon 吊死）。
//! - 全部时间由调用方注入（Unix 毫秒），单测不依赖系统钟。

use std::collections::HashMap;
use std::time::Duration;

/// 生产参数：空载 5 分钟自退
pub const IDLE_EXIT_AFTER: Duration = Duration::from_secs(5 * 60);
/// 生产参数：24h 无事件视为僵死
pub const ZOMBIE_AFTER: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Default)]
pub struct SessionTracker {
    /// session_id -> 最后一次事件 ts（Unix 毫秒）
    sessions: HashMap<String, i64>,
    /// 集合变空的时刻（SessionEnd 的事件 ts，或首次巡检的 now）；非空时为 None
    empty_since: Option<i64>,
}

impl SessionTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// 喂入一条事件。event = 事件名（SessionStart/SessionEnd/...），ts = 事件 Unix 毫秒。
    pub fn on_event(&mut self, event: &str, session_id: &str, ts: i64) {
        if session_id.is_empty() {
            return; // 降级产物不跟踪
        }
        if event == "SessionEnd" {
            self.sessions.remove(session_id);
            if self.sessions.is_empty() && self.empty_since.is_none() {
                self.empty_since = Some(ts);
            }
            return;
        }
        // Start / Heartbeat / PreToolUse 等一律 upsert 刷新
        self.sessions.insert(session_id.to_string(), ts);
        self.empty_since = None;
    }

    /// 周期巡检：先清僵死，再判空载。返回 true = 空载持续超 idle_timeout，该自退了。
    pub fn should_exit(
        &mut self,
        now: i64,
        idle_timeout: Duration,
        zombie_after: Duration,
    ) -> bool {
        let zombie_ms = zombie_after.as_millis() as i64;
        self.sessions.retain(|_, last| now - *last <= zombie_ms);

        if !self.sessions.is_empty() {
            self.empty_since = None;
            return false;
        }
        let since = self.empty_since.get_or_insert(now);
        now - *since >= idle_timeout.as_millis() as i64
    }

    /// 当前活跃会话数（托盘状态/测试用）
    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: i64 = 60_000;
    const HOUR: i64 = 3_600_000;

    #[test]
    fn start_adds_end_removes() {
        let mut t = SessionTracker::new();
        t.on_event("SessionStart", "s1", 1_000);
        t.on_event("SessionStart", "s2", 2_000);
        assert_eq!(t.active_count(), 2);
        t.on_event("SessionEnd", "s1", 3_000);
        assert_eq!(t.active_count(), 1);
        t.on_event("SessionEnd", "s2", 4_000);
        assert_eq!(t.active_count(), 0);
    }

    #[test]
    fn heartbeat_and_pretool_upsert_unknown_session() {
        let mut t = SessionTracker::new();
        // daemon 重启后错过 Start：Heartbeat 补记
        t.on_event("SessionHeartbeat", "s1", 1_000);
        assert_eq!(t.active_count(), 1);
        // PreToolUse 同样是活跃证据
        t.on_event("PreToolUse", "s2", 2_000);
        assert_eq!(t.active_count(), 2);
    }

    #[test]
    fn empty_session_id_ignored() {
        let mut t = SessionTracker::new();
        t.on_event("SessionStart", "", 1_000);
        assert_eq!(t.active_count(), 0);
    }

    #[test]
    fn idle_exit_only_after_timeout() {
        let mut t = SessionTracker::new();
        t.on_event("SessionStart", "s1", 0);
        t.on_event("SessionEnd", "s1", 10 * MIN);
        // 空载 4 分钟：不退
        assert!(!t.should_exit(
            14 * MIN,
            Duration::from_millis((5 * MIN) as u64),
            Duration::from_millis((24 * HOUR) as u64)
        ));
        // 空载 5 分钟整：退
        assert!(t.should_exit(
            15 * MIN,
            Duration::from_millis((5 * MIN) as u64),
            Duration::from_millis((24 * HOUR) as u64)
        ));
    }

    #[test]
    fn idle_clock_starts_from_end_event_ts_not_first_tick() {
        let mut t = SessionTracker::new();
        t.on_event("SessionEnd", "s1", 10 * MIN); // 结束即空（本就没 Start 记录也成立）
                                                  // 第一次巡检距 End 已 4 分 59 秒
        assert!(!t.should_exit(
            14 * MIN + 59_000,
            Duration::from_millis((5 * MIN) as u64),
            Duration::from_millis((24 * HOUR) as u64)
        ));
        assert!(t.should_exit(
            15 * MIN,
            Duration::from_millis((5 * MIN) as u64),
            Duration::from_millis((24 * HOUR) as u64)
        ));
    }

    #[test]
    fn new_activity_resets_idle_clock() {
        let mut t = SessionTracker::new();
        t.on_event("SessionEnd", "s1", 10 * MIN);
        assert!(!t.should_exit(
            12 * MIN,
            Duration::from_millis((5 * MIN) as u64),
            Duration::from_millis((24 * HOUR) as u64)
        ));
        // 新会话开始：空载计时清零
        t.on_event("SessionStart", "s2", 13 * MIN);
        assert!(!t.should_exit(
            18 * MIN,
            Duration::from_millis((5 * MIN) as u64),
            Duration::from_millis((24 * HOUR) as u64)
        ));
        assert_eq!(t.active_count(), 1);
    }

    #[test]
    fn zombie_session_purged_after_24h() {
        let mut t = SessionTracker::new();
        t.on_event("SessionStart", "s1", 0);
        // 25h 无事件（崩溃/kill 不会发 SessionEnd）：巡检时按僵死清除
        let exit = t.should_exit(
            25 * HOUR,
            Duration::from_millis((5 * MIN) as u64),
            Duration::from_millis((24 * HOUR) as u64),
        );
        assert_eq!(t.active_count(), 0, "僵死会话必须清除");
        // 清除后集合刚空：empty_since = 本次 now，未到 5 分钟暂不退
        assert!(!exit);
        // 再空载 5 分钟：退
        assert!(t.should_exit(
            25 * HOUR + 5 * MIN,
            Duration::from_millis((5 * MIN) as u64),
            Duration::from_millis((24 * HOUR) as u64)
        ));
    }

    #[test]
    fn fresh_daemon_exits_after_idle_timeout() {
        let mut t = SessionTracker::new();
        // 全新 daemon（无任何事件）：首次巡检起算空载
        assert!(!t.should_exit(
            100 * MIN,
            Duration::from_millis((5 * MIN) as u64),
            Duration::from_millis((24 * HOUR) as u64)
        ));
        assert!(!t.should_exit(
            104 * MIN,
            Duration::from_millis((5 * MIN) as u64),
            Duration::from_millis((24 * HOUR) as u64)
        ));
        assert!(t.should_exit(
            105 * MIN,
            Duration::from_millis((5 * MIN) as u64),
            Duration::from_millis((24 * HOUR) as u64)
        ));
    }

    #[test]
    fn heartbeat_before_deadline_prevents_exit() {
        let mut t = SessionTracker::new();
        t.on_event("SessionStart", "s1", 0);
        t.on_event("SessionHeartbeat", "s1", 23 * HOUR);
        // 距最后心跳 2h：未僵死、不退
        assert!(!t.should_exit(
            25 * HOUR,
            Duration::from_millis((5 * MIN) as u64),
            Duration::from_millis((24 * HOUR) as u64)
        ));
        assert_eq!(t.active_count(), 1);
    }
}
