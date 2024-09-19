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
pub struct InsertPkU256 {
    pub n: __sats::u256,
    pub data: i32,
}

impl __sdk::spacetime_module::InModule for InsertPkU256 {
    type Module = super::RemoteModule;
}

pub struct InsertPkU256CallbackId(__sdk::callbacks::CallbackId);

#[allow(non_camel_case_types)]
pub trait insert_pk_u_256 {
    fn insert_pk_u_256(&self, n: __sats::u256, data: i32) -> __anyhow::Result<()>;
    fn on_insert_pk_u_256(
        &self,
        callback: impl FnMut(&super::EventContext, &__sats::u256, &i32) + Send + 'static,
    ) -> InsertPkU256CallbackId;
    fn remove_on_insert_pk_u_256(&self, callback: InsertPkU256CallbackId);
}

impl insert_pk_u_256 for super::RemoteReducers {
    fn insert_pk_u_256(&self, n: __sats::u256, data: i32) -> __anyhow::Result<()> {
        self.imp.call_reducer("insert_pk_u256", InsertPkU256 { n, data })
    }
    fn on_insert_pk_u_256(
        &self,
        mut callback: impl FnMut(&super::EventContext, &__sats::u256, &i32) + Send + 'static,
    ) -> InsertPkU256CallbackId {
        InsertPkU256CallbackId(self.imp.on_reducer::<InsertPkU256>(
            "insert_pk_u256",
            Box::new(move |ctx: &super::EventContext, args: &InsertPkU256| callback(ctx, &args.n, &args.data)),
        ))
    }
    fn remove_on_insert_pk_u_256(&self, callback: InsertPkU256CallbackId) {
        self.imp.remove_on_reducer::<InsertPkU256>("insert_pk_u256", callback.0)
    }
}
