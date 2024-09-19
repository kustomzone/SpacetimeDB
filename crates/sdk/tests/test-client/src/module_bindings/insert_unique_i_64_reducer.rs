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
pub struct InsertUniqueI64 {
    pub n: i64,
    pub data: i32,
}

impl __sdk::spacetime_module::InModule for InsertUniqueI64 {
    type Module = super::RemoteModule;
}

pub struct InsertUniqueI64CallbackId(__sdk::callbacks::CallbackId);

#[allow(non_camel_case_types)]
pub trait insert_unique_i_64 {
    fn insert_unique_i_64(&self, n: i64, data: i32) -> __anyhow::Result<()>;
    fn on_insert_unique_i_64(
        &self,
        callback: impl FnMut(&super::EventContext, &i64, &i32) + Send + 'static,
    ) -> InsertUniqueI64CallbackId;
    fn remove_on_insert_unique_i_64(&self, callback: InsertUniqueI64CallbackId);
}

impl insert_unique_i_64 for super::RemoteReducers {
    fn insert_unique_i_64(&self, n: i64, data: i32) -> __anyhow::Result<()> {
        self.imp.call_reducer("insert_unique_i64", InsertUniqueI64 { n, data })
    }
    fn on_insert_unique_i_64(
        &self,
        mut callback: impl FnMut(&super::EventContext, &i64, &i32) + Send + 'static,
    ) -> InsertUniqueI64CallbackId {
        InsertUniqueI64CallbackId(self.imp.on_reducer::<InsertUniqueI64>(
            "insert_unique_i64",
            Box::new(move |ctx: &super::EventContext, args: &InsertUniqueI64| callback(ctx, &args.n, &args.data)),
        ))
    }
    fn remove_on_insert_unique_i_64(&self, callback: InsertUniqueI64CallbackId) {
        self.imp
            .remove_on_reducer::<InsertUniqueI64>("insert_unique_i64", callback.0)
    }
}
