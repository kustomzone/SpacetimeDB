use hyper::upgrade::Upgraded;
use lazy_static::lazy_static;
use std::{collections::HashMap, sync::Mutex, time::Duration};
use tokio::{task::JoinHandle, time::sleep};
use tokio_tungstenite::tungstenite::protocol::Message as WebSocketMessage;
use tokio_tungstenite::WebSocketStream;
use super::worker_connection::WorkerConnection;

lazy_static! {
    pub static ref WORKER_CONNECTION_INDEX: Mutex<WorkerConnectionIndex> = {
        Mutex::new(WorkerConnectionIndex {
            id_index: HashMap::new(),
            connections: Vec::new(),
            liveliness_check_handle: None,
        })
    };
}

#[derive(PartialEq, Eq, Clone, Copy, Hash)]
struct Pointer(usize);

pub struct WorkerConnectionIndex {
    id_index: HashMap<u64, Pointer>,
    pub connections: Vec<WorkerConnection>,
    liveliness_check_handle: Option<JoinHandle<()>>,
}

impl WorkerConnectionIndex {
    pub fn start_liveliness_check() {
        let mut wci = WORKER_CONNECTION_INDEX.lock().unwrap();
        if wci.liveliness_check_handle.is_some() {
            return;
        }
        wci.liveliness_check_handle = Some(tokio::spawn(async move {
            loop {
                log::trace!("Beginning worker liveliness check");
                let futures = {
                    let mut wci = WORKER_CONNECTION_INDEX.lock().unwrap();
                    let mut futures = Vec::new();
                    let mut i = 0;
                    while i < wci.connections.len() {
                        let alive = wci.connections[i].alive;
                        let id = wci.connections[i].id;
                        if !alive {
                            // Drop it like it's hot.
                            log::trace!("Dropping dead worker {}", id);
                            wci.drop_client(&id);
                            continue;
                        }
                        let client = &mut wci.connections[i];
                        client.alive = false;
                        let sender = client.sender();
                        log::trace!("Pinging worker {}", id);
                        futures.push(sender.send(WebSocketMessage::Ping(Vec::new())));
                        i += 1;
                    }
                    futures
                };
                futures::future::join_all(futures).await;
                sleep(Duration::from_secs(10)).await;
            }
        }));
    }

    pub fn get_client(&self, id: &u64) -> Option<&WorkerConnection> {
        let index = self.id_index.get(id);
        if let Some(i) = index {
            return Some(self.connections.get(i.0).unwrap());
        }
        return None;
    }

    pub fn get_client_mut(&mut self, id: &u64) -> Option<&mut WorkerConnection> {
        let index = self.id_index.get_mut(id);
        if let Some(i) = index {
            return Some(self.connections.get_mut(i.0).unwrap());
        }
        return None;
    }

    pub fn drop_client(&mut self, id: &u64) {
        let index = self.id_index.remove(id);
        if let Some(index) = index {
            // Swizzle around the indexes to match the swap remove
            self.connections.swap_remove(index.0);
            let last = self.connections.get(index.0);
            if let Some(last) = last {
                let last_id = last.id;
                self.id_index.insert(last_id, index);
            }
        }
    }

    pub fn new_client(
        &mut self,
        worker_id: u64,
        ws: WebSocketStream<Upgraded>,
    ) -> u64 {
        let pointer = Pointer(self.connections.len());

        let mut worker = WorkerConnection::new(worker_id, ws);

        // NOTE: Begin receiving when we create a new client. This only really works
        // because authentication is provided in the headers of the request. That is to say,
        // by the time we're creating a client connection, we already know that this is
        // a valid client actor connection
        worker.recv();
        self.connections.push(worker);

        // Update id index
        self.id_index.insert(worker_id, pointer);

        worker_id
    }
}