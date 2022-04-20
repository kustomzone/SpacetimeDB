use gotham::anyhow::anyhow;
use gotham::handler::HandlerError;
use gotham::handler::SimpleHandlerResult;
use gotham::prelude::StaticResponseExtender;
use gotham::router::builder::*;
use gotham::prelude::FromState;
use gotham::router::Router;
use gotham::state::State;
use gotham::state::StateData;
use hyper::Body;
use hyper::body::HttpBody;
use hyper::{Response, StatusCode};
use serde::Deserialize;
use crate::api;

#[derive(Deserialize, StateData, StaticResponseExtender)]
struct DatabaseInitParams {
    namespace: String,
    name: String,
}

async fn init_database(state: &mut State) -> SimpleHandlerResult {
    let DatabaseInitParams { namespace, name } = DatabaseInitParams::take_from(state);
    let body = state.borrow_mut::<Body>();
    let data = body.data().await;
    if data.is_none() {
        return Err(
            HandlerError::from(anyhow!("Missing request body."))
            .with_status(StatusCode::BAD_REQUEST)
        );
    }
    let data = data.unwrap();
    let wasm_bytecode = data.unwrap();

    api::database::init(namespace, name, wasm_bytecode);
    
    let res = Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap();

    Ok(res)
}

pub fn router() -> Router {
    build_simple_router(|route| {
        route.get("/").to(|state| (state, "Hello, World!"));
        route
            .post("/database/init/:namespace/:name")
            .with_path_extractor::<DatabaseInitParams>()
            .to_async_borrowing(init_database);
        // route.delegate("/auth").to_router(auth_router());
        // route.delegate("/admin").to_router(admin_router());
        // route.delegate("/metrics").to_router(metrics_router());
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use gotham::test::TestServer;

    #[test]
    fn init_database() {
        let test_server = TestServer::new(router()).unwrap();
        let uri = "http://localhost/database/init/clockworklabs/bitcraft";
        let body = Body::empty();
        let mime = "application/octet-stream".parse().unwrap();
        let response = test_server
            .client()
            .post(uri, body, mime)
            .perform()
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}