pub(crate) mod worker_api;
pub(crate) mod client_api; // TODO: should be private
pub(crate) mod control_db;
mod object_db;
mod controller;
use futures::{future::join_all, FutureExt};

pub async fn start(config: crate::nodes::node_config::NodeConfig) {
    join_all(vec![
        worker_api::start(config).boxed(),
        client_api::start(26258).boxed(),
    ]).await;
}