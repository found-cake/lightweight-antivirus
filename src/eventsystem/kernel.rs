use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, PartialEq)]
pub enum EventType {
    FileOpen = 1,
    FileWrite = 2,
    FileDelete = 3,
    ProcessCreate = 4,
    ProcessTerminate = 5,
}

#[derive(Debug, Clone, PartialEq)]
pub struct KernelEvent {
    pub event_type: EventType,
    pub pid: u32,
    pub process_path: Arc<str>,
    pub file_path: Arc<str>,
    pub op_id: u64,
    pub flags: u32,
    pub timestamp: u64,
}

impl KernelEvent {
    pub fn new(
        event_type: EventType,
        pid: u32,
        process_path: String,
        file_path: String,
        flags: u32,
    ) -> Self {
        Self {
            event_type,
            pid,
            process_path: process_path.into(),
            file_path: file_path.into(),
            op_id: generate_op_id(),
            flags,
            timestamp: current_timestamp(),
        }
    }
}

fn generate_op_id() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);

    if id == 0 {
        COUNTER.fetch_add(1, Ordering::Relaxed)
    } else {
        id
    }
}

fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time is before UNIX epoch")
        .as_millis() as u64
}
