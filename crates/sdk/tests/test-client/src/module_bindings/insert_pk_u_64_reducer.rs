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
pub struct InsertPkU64 {
    pub n: u64,
    pub data: i32,
}

impl __sdk::spacetime_module::InModule for InsertPkU64 {
    type Module = super::RemoteModule;
}

pub struct InsertPkU64CallbackId(__sdk::callbacks::CallbackId);

#[allow(non_camel_case_types)]
pub trait insert_pk_u_64 {
    fn insert_pk_u_64(&self, n: u64, data: i32) -> __anyhow::Result<()>;
    fn on_insert_pk_u_64(
        &self,
        callback: impl FnMut(&super::EventContext, &u64, &i32) + Send + 'static,
    ) -> InsertPkU64CallbackId;
    fn remove_on_insert_pk_u_64(&self, callback: InsertPkU64CallbackId);
}

impl insert_pk_u_64 for super::RemoteReducers {
    fn insert_pk_u_64(&self, n: u64, data: i32) -> __anyhow::Result<()> {
        self.imp.call_reducer("insert_pk_u64", InsertPkU64 { n, data })
    }
    fn on_insert_pk_u_64(
        &self,
        mut callback: impl FnMut(&super::EventContext, &u64, &i32) + Send + 'static,
    ) -> InsertPkU64CallbackId {
        InsertPkU64CallbackId(self.imp.on_reducer::<InsertPkU64>(
            "insert_pk_u64",
            Box::new(move |ctx: &super::EventContext, args: &InsertPkU64| callback(ctx, &args.n, &args.data)),
        ))
    }
    fn remove_on_insert_pk_u_64(&self, callback: InsertPkU64CallbackId) {
        self.imp.remove_on_reducer::<InsertPkU64>("insert_pk_u64", callback.0)
    }
}
