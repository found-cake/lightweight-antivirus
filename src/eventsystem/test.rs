use crate::eventsystem::EventSystem;
use crate::eventsystem::kernel::{EventType, KernelEvent};
use crate::eventsystem::user::{UserVerdict, Verdict};

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
        reason_code: 1001, // 악성코드 탐지 정책 id
        ttl_ms: None,
    };
    user.verdict_tx.send(verdict).await.unwrap();

    // 커널이 판결 수신
    let received_verdict = kernel.verdict_rx.recv().await.unwrap();
    assert_eq!(received_verdict.op_id, op_id);
    assert_eq!(received_verdict.verdict, Verdict::Deny);
}

#[tokio::test]
async fn test_concurrent_event_processing() {
    let mut system = EventSystem::new(100);
    let mut kernel = system.take_kernel_handles();
    let mut user = system.take_user_handles();

    let kernel_task = tokio::spawn(async move {
        let events = vec![
            ("notepad.exe", "document.txt", EventType::FileOpen),
            ("notepad.exe", "document.txt", EventType::FileWrite),
            ("notepad.exe", "document.txt", EventType::FileWrite),
            ("chrome.exe", "malware.exe", EventType::FileOpen),
            ("explorer.exe", "temp.txt", EventType::FileDelete),
        ];

        let mut op_ids = Vec::new();
        for (process, file, event_type) in events {
            let event = KernelEvent::new(
                event_type,
                1234,
                format!("C:\\{}", process),
                format!("C:\\{}", file),
                0,
            );
            op_ids.push(event.op_id);
            kernel.event_tx.send(event).await.unwrap();

            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }

        for expected_op_id in &op_ids {
            let verdict = kernel.verdict_rx.recv().await.unwrap();
            assert!(op_ids.contains(&verdict.op_id));
            println!("{}", expected_op_id);
        }

        op_ids
    });

    let user_task = tokio::spawn(async move {
        let mut processed = Vec::new();

        for _ in 0..5 {
            let event = user.event_rx.recv().await.unwrap();
            processed.push(event.op_id);

            tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

            let verdict = if event.file_path.contains("malware") {
                UserVerdict {
                    op_id: event.op_id,
                    verdict: Verdict::Deny,
                    reason_code: 1001,
                    ttl_ms: None,
                }
            } else if event.file_path.contains("document") || event.file_path.contains("temp") {
                UserVerdict {
                    op_id: event.op_id,
                    verdict: Verdict::Defer,
                    reason_code: 0,
                    ttl_ms: Some(5000),
                }
            } else {
                UserVerdict {
                    op_id: event.op_id,
                    verdict: Verdict::Allow,
                    reason_code: 0,
                    ttl_ms: None,
                }
            };

            user.verdict_tx.send(verdict).await.unwrap();
        }

        processed
    });

    let (kernel_ids, user_ids) = tokio::join!(kernel_task, user_task);
    let kernel_ids = kernel_ids.unwrap();
    let user_ids = user_ids.unwrap();

    assert_eq!(kernel_ids.len(), 5);
    assert_eq!(user_ids.len(), 5);
}
