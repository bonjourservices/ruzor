use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::client::BatchClient;
use crate::config::Address;

const FORWARDER_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug)]
struct ForwardRequest {
    digest: String,
    whitelist: bool,
}

#[derive(Clone)]
pub struct Forwarder {
    sender: SyncSender<ForwardRequest>,
}

impl Forwarder {
    pub fn queue_forward_request(&self, digest: &str, whitelist: bool) {
        let request = ForwardRequest {
            digest: digest.to_string(),
            whitelist,
        };
        let _ = self.sender.try_send(request);
    }
}

impl fmt::Debug for Forwarder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Forwarder").finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct ForwarderHandle {
    forwarder: Forwarder,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl ForwarderHandle {
    pub fn start(client: BatchClient, remote_servers: Vec<Address>, max_queue_size: usize) -> Self {
        let (sender, receiver) = sync_channel(max_queue_size);
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let handle = thread::spawn(move || {
            forward_loop(client, remote_servers, receiver, worker_shutdown);
        });
        Self {
            forwarder: Forwarder { sender },
            shutdown,
            handle: Some(handle),
        }
    }

    pub fn forwarder(&self) -> Forwarder {
        self.forwarder.clone()
    }

    pub fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for ForwarderHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

fn forward_loop(
    mut client: BatchClient,
    remote_servers: Vec<Address>,
    receiver: Receiver<ForwardRequest>,
    shutdown: Arc<AtomicBool>,
) {
    loop {
        match receiver.recv_timeout(FORWARDER_TIMEOUT) {
            Ok(request) => forward_one(&mut client, &remote_servers, request),
            Err(RecvTimeoutError::Timeout) if shutdown.load(Ordering::Relaxed) => break,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    while let Ok(request) = receiver.try_recv() {
        forward_one(&mut client, &remote_servers, request);
    }
    client.force();
}

fn forward_one(client: &mut BatchClient, remote_servers: &[Address], request: ForwardRequest) {
    for server in remote_servers {
        let result = if request.whitelist {
            client.whitelist(&request.digest, server)
        } else {
            client.report(&request.digest, server)
        };
        let _ = result;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_forward_request_never_exceeds_channel_capacity() {
        let (sender, receiver) = sync_channel(10);
        let forwarder = Forwarder { sender };

        for index in 0..20 {
            forwarder
                .queue_forward_request("975422c090e7a43ab7c9bf0065d5b661259e6d74", index % 2 == 0);
        }

        let queued: Vec<_> = receiver.try_iter().collect();
        assert_eq!(queued.len(), 10);
        assert!(
            queued
                .iter()
                .all(|request| request.digest == "975422c090e7a43ab7c9bf0065d5b661259e6d74")
        );
    }
}
