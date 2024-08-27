// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN RUST INSTEAD.

#![allow(unused_imports)]
use spacetimedb_sdk::callbacks::{DbCallbacks, ReducerCallbacks};
use spacetimedb_sdk::client_cache::{ClientCache, RowCallbackReminders};
use spacetimedb_sdk::global_connection::with_connection_mut;
use spacetimedb_sdk::identity::Credentials;
use spacetimedb_sdk::reducer::AnyReducerEvent;
use spacetimedb_sdk::spacetime_module::SpacetimeModule;
use spacetimedb_sdk::ws_messages::{TableUpdate, TransactionUpdate};
use spacetimedb_sdk::{
    anyhow::{anyhow, Result},
    identity::Identity,
    reducer::{Reducer, ReducerCallbackId, Status},
    sats::{de::Deserialize, ser::Serialize},
    spacetimedb_lib,
    table::{TableIter, TableType, TableWithPrimaryKey},
    Address,
};
use std::sync::Arc;

pub mod message;
pub mod send_message_reducer;
pub mod set_name_reducer;
pub mod user;

pub use message::*;
pub use send_message_reducer::*;
pub use set_name_reducer::*;
pub use user::*;

#[allow(unused)]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum ReducerEvent {
    SendMessage(send_message_reducer::SendMessageArgs),
    SetName(set_name_reducer::SetNameArgs),
}

#[allow(unused)]
pub struct Module;
impl SpacetimeModule for Module {
    fn handle_table_update(
        &self,
        table_update: TableUpdate,
        client_cache: &mut ClientCache,
        callbacks: &mut RowCallbackReminders,
    ) {
        let table_name = &table_update.table_name[..];
        match table_name {
            "Message" => client_cache.handle_table_update_no_primary_key::<message::Message>(callbacks, table_update),
            "User" => client_cache.handle_table_update_with_primary_key::<user::User>(callbacks, table_update),
            _ => spacetimedb_sdk::log::error!("TableRowOperation on unknown table {:?}", table_name),
        }
    }
    fn invoke_row_callbacks(
        &self,
        reminders: &mut RowCallbackReminders,
        worker: &mut DbCallbacks,
        reducer_event: Option<Arc<AnyReducerEvent>>,
        state: &Arc<ClientCache>,
    ) {
        reminders.invoke_callbacks::<message::Message>(worker, &reducer_event, state);
        reminders.invoke_callbacks::<user::User>(worker, &reducer_event, state);
    }
    fn handle_event(
        &self,
        event: TransactionUpdate,
        _reducer_callbacks: &mut ReducerCallbacks,
        _state: Arc<ClientCache>,
    ) -> Option<Arc<AnyReducerEvent>> {
        let reducer_call = &event.reducer_call;
        #[allow(clippy::match_single_binding)]
        match &reducer_call.reducer_name[..] {
            "send_message" => _reducer_callbacks
                .handle_event_of_type::<send_message_reducer::SendMessageArgs, ReducerEvent>(
                    event,
                    _state,
                    ReducerEvent::SendMessage,
                ),
            "set_name" => _reducer_callbacks.handle_event_of_type::<set_name_reducer::SetNameArgs, ReducerEvent>(
                event,
                _state,
                ReducerEvent::SetName,
            ),
            unknown => {
                spacetimedb_sdk::log::error!("Event on an unknown reducer: {:?}", unknown);
                None
            }
        }
    }
    fn handle_resubscribe(
        &self,
        new_subs: TableUpdate,
        client_cache: &mut ClientCache,
        callbacks: &mut RowCallbackReminders,
    ) {
        let table_name = &new_subs.table_name[..];
        match table_name {
            "Message" => client_cache.handle_resubscribe_for_type::<message::Message>(callbacks, new_subs),
            "User" => client_cache.handle_resubscribe_for_type::<user::User>(callbacks, new_subs),
            _ => spacetimedb_sdk::log::error!("TableRowOperation on unknown table {:?}", table_name),
        }
    }
}

/// Connect to a database named `db_name` accessible over the internet at the URI `spacetimedb_uri`.
///
/// If `credentials` are supplied, they will be passed to the new connection to
/// identify and authenticate the user. Otherwise, a set of `Credentials` will be
/// generated by the server.
pub fn connect<IntoUri>(
    spacetimedb_uri: IntoUri,
    db_name: &str,
    credentials: Option<Credentials>,
    compression: Option<spacetimedb_sdk::websocket::Compression>,
) -> Result<()>
where
    IntoUri: TryInto<spacetimedb_sdk::http::Uri>,
    <IntoUri as TryInto<spacetimedb_sdk::http::Uri>>::Error: std::error::Error + Send + Sync + 'static,
{
    with_connection_mut(|connection| {
        connection.connect(spacetimedb_uri, db_name, credentials, compression, Arc::new(Module))?;
        Ok(())
    })
}
