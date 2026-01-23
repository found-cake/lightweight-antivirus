use tokio::sync::mpsc::{channel, Sender, Receiver};
use crate::eventsystem::{kernel::KernelEvent, user::UserVerdict};

pub mod kernel;
pub mod user;

pub struct EventSystem {
    event_tx: Sender<KernelEvent>,
    event_rx: Option<Receiver<KernelEvent>>,
    verdict_tx: Sender<UserVerdict>,
    verdict_rx: Option<Receiver<UserVerdict>>,
}

impl EventSystem {
    pub fn new(buffer_size: usize) -> Self {
        let (event_tx, event_rx) = channel(buffer_size);
        let (verdict_tx, verdict_rx) = channel(buffer_size);
        
        Self {
            event_tx,
            event_rx: Some(event_rx),
            verdict_tx,
            verdict_rx: Some(verdict_rx),
        }
    }
    
    pub fn take_kernel_handles(&mut self) -> KernelHandles {
        KernelHandles {
            event_tx: self.event_tx.clone(),
            verdict_rx: self.verdict_rx.take().expect("verdict_rx already taken"),
        }
    }
    
    pub fn take_user_handles(&mut self) -> UserHandles {
        UserHandles {
            event_rx: self.event_rx.take().expect("event_rx already taken"),
            verdict_tx: self.verdict_tx.clone(),
        }
    }
}

pub struct KernelHandles {
    pub event_tx: Sender<KernelEvent>,
    pub verdict_rx: Receiver<UserVerdict>,
}

pub struct UserHandles {
    pub event_rx: Receiver<KernelEvent>,
    pub verdict_tx: Sender<UserVerdict>,
}
