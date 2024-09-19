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
pub struct InsertOneI8 {
    pub n: i8,
}

impl __sdk::spacetime_module::InModule for InsertOneI8 {
    type Module = super::RemoteModule;
}

pub struct InsertOneI8CallbackId(__sdk::callbacks::CallbackId);

#[allow(non_camel_case_types)]
pub trait insert_one_i_8 {
    fn insert_one_i_8(&self, n: i8) -> __anyhow::Result<()>;
    fn on_insert_one_i_8(
        &self,
        callback: impl FnMut(&super::EventContext, &i8) + Send + 'static,
    ) -> InsertOneI8CallbackId;
    fn remove_on_insert_one_i_8(&self, callback: InsertOneI8CallbackId);
}

impl insert_one_i_8 for super::RemoteReducers {
    fn insert_one_i_8(&self, n: i8) -> __anyhow::Result<()> {
        self.imp.call_reducer("insert_one_i8", InsertOneI8 { n })
    }
    fn on_insert_one_i_8(
        &self,
        mut callback: impl FnMut(&super::EventContext, &i8) + Send + 'static,
    ) -> InsertOneI8CallbackId {
        InsertOneI8CallbackId(self.imp.on_reducer::<InsertOneI8>(
            "insert_one_i8",
            Box::new(move |ctx: &super::EventContext, args: &InsertOneI8| callback(ctx, &args.n)),
        ))
    }
    fn remove_on_insert_one_i_8(&self, callback: InsertOneI8CallbackId) {
        self.imp.remove_on_reducer::<InsertOneI8>("insert_one_i8", callback.0)
    }
}
