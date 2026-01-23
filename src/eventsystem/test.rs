use crate::eventsystem::EventSystem;
use crate::eventsystem::kernel::{EventType, KernelEvent};
use crate::eventsystem::user::{UserVerdict, Verdict};

#[tokio::test]
async fn test_event_system_basic_flow() {
    let mut system = EventSystem::new(100);
    let mut kernel = system.take_kernel_handles();
    let mut user = system.take_user_handles();

    let event = KernelEvent::new(
        EventType::FileOpen,
        1234,
        "C:\\Windows\\System32\\cmd.exe".to_string(),
        "C:\\suspicious\\malware.exe".to_string(),
        0,
    );
    let op_id = event.op_id;
    kernel.event_tx.send(event).await.unwrap();

    let received_event = user.event_rx.recv().await.unwrap();
    assert_eq!(received_event.op_id, op_id);
    assert_eq!(received_event.event_type, EventType::FileOpen);
    assert_eq!(received_event.pid, 1234);

    let verdict = UserVerdict {
        op_id,
        verdict: Verdict::Deny,
        reason_code: 1001, // 악성코드 탐지
    };
    user.verdict_tx.send(verdict).await.unwrap();

    // 커널이 판결 수신
    let received_verdict = kernel.verdict_rx.recv().await.unwrap();
    assert_eq!(received_verdict.op_id, op_id);
    assert_eq!(received_verdict.verdict, Verdict::Deny);
}

#[test]
fn test_op_id_generation() {
    let event1 = KernelEvent::new(
        EventType::FileOpen,
        1,
        "test1".to_string(),
        "file1".to_string(),
        0,
    );
    
    let event2 = KernelEvent::new(
        EventType::FileWrite,
        2,
        "test2".to_string(),
        "file2".to_string(),
        0,
    );

    // op_id는 순차적으로 증가해야 함
    assert!(event2.op_id > event1.op_id);
}