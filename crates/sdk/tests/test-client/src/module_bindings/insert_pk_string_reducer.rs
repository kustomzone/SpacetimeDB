// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN RUST INSTEAD.

#![allow(unused)]
use spacetimedb_sdk::{
    self as __sdk,
    anyhow::{self as __anyhow, Context as _},
    lib as __lib, sats as __sats, ws_messages as __ws,
};

#[derive(__lib::ser::Serialize, __lib::de::Deserialize, Clone, PartialEq, Debug)]
#[sats(crate = __lib)]
pub struct InsertPkString {
    pub s: String,
    pub data: i32,
}

impl __sdk::spacetime_module::InModule for InsertPkString {
    type Module = super::RemoteModule;
}

pub struct InsertPkStringCallbackId(__sdk::callbacks::CallbackId);

#[allow(non_camel_case_types)]
pub trait insert_pk_string {
    fn insert_pk_string(&self, s: String, data: i32) -> __anyhow::Result<()>;
    fn on_insert_pk_string(
        &self,
        callback: impl FnMut(&super::EventContext, &String, &i32) + Send + 'static,
    ) -> InsertPkStringCallbackId;
    fn remove_on_insert_pk_string(&self, callback: InsertPkStringCallbackId);
}

impl insert_pk_string for super::RemoteReducers {
    fn insert_pk_string(&self, s: String, data: i32) -> __anyhow::Result<()> {
        self.imp.call_reducer("insert_pk_string", InsertPkString { s, data })
    }
    fn on_insert_pk_string(
        &self,
        mut callback: impl FnMut(&super::EventContext, &String, &i32) + Send + 'static,
    ) -> InsertPkStringCallbackId {
        InsertPkStringCallbackId(self.imp.on_reducer::<InsertPkString>(
            "insert_pk_string",
            Box::new(move |ctx: &super::EventContext, args: &InsertPkString| callback(ctx, &args.s, &args.data)),
        ))
    }
    fn remove_on_insert_pk_string(&self, callback: InsertPkStringCallbackId) {
        self.imp
            .remove_on_reducer::<InsertPkString>("insert_pk_string", callback.0)
    }
}
