//! 测试公共件：用完即删的临时目录（GOAL 任务 6：kcg-test-*/kcg-bypass-* 不再漏进 TEMP）。
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

/// 临时目录守卫：创建即建目录，Drop 即整树删除
pub struct TempDir(pub PathBuf);

impl TempDir {
    /// 目录名 = `{prefix}-{tag}-{pid}-{序号}`（prefix 只能是 kcg-test / kcg-bypass 家族）
    pub fn new(prefix: &str, tag: &str) -> Self {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("{prefix}-{tag}-{}-{n}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}

impl std::ops::Deref for TempDir {
    type Target = PathBuf;
    fn deref(&self) -> &PathBuf {
        &self.0
    }
}

impl AsRef<Path> for TempDir {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
