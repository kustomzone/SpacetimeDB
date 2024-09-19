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
pub struct InsertPkI128 {
    pub n: i128,
    pub data: i32,
}

impl __sdk::spacetime_module::InModule for InsertPkI128 {
    type Module = super::RemoteModule;
}

pub struct InsertPkI128CallbackId(__sdk::callbacks::CallbackId);

#[allow(non_camel_case_types)]
pub trait insert_pk_i_128 {
    fn insert_pk_i_128(&self, n: i128, data: i32) -> __anyhow::Result<()>;
    fn on_insert_pk_i_128(
        &self,
        callback: impl FnMut(&super::EventContext, &i128, &i32) + Send + 'static,
    ) -> InsertPkI128CallbackId;
    fn remove_on_insert_pk_i_128(&self, callback: InsertPkI128CallbackId);
}

impl insert_pk_i_128 for super::RemoteReducers {
    fn insert_pk_i_128(&self, n: i128, data: i32) -> __anyhow::Result<()> {
        self.imp.call_reducer("insert_pk_i128", InsertPkI128 { n, data })
    }
    fn on_insert_pk_i_128(
        &self,
        mut callback: impl FnMut(&super::EventContext, &i128, &i32) + Send + 'static,
    ) -> InsertPkI128CallbackId {
        InsertPkI128CallbackId(self.imp.on_reducer::<InsertPkI128>(
            "insert_pk_i128",
            Box::new(move |ctx: &super::EventContext, args: &InsertPkI128| callback(ctx, &args.n, &args.data)),
        ))
    }
    fn remove_on_insert_pk_i_128(&self, callback: InsertPkI128CallbackId) {
        self.imp.remove_on_reducer::<InsertPkI128>("insert_pk_i128", callback.0)
    }
}
