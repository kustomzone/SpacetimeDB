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
pub struct InsertUniqueI8 {
    pub n: i8,
    pub data: i32,
}

impl __sdk::spacetime_module::InModule for InsertUniqueI8 {
    type Module = super::RemoteModule;
}

pub struct InsertUniqueI8CallbackId(__sdk::callbacks::CallbackId);

#[allow(non_camel_case_types)]
pub trait insert_unique_i_8 {
    fn insert_unique_i_8(&self, n: i8, data: i32) -> __anyhow::Result<()>;
    fn on_insert_unique_i_8(
        &self,
        callback: impl FnMut(&super::EventContext, &i8, &i32) + Send + 'static,
    ) -> InsertUniqueI8CallbackId;
    fn remove_on_insert_unique_i_8(&self, callback: InsertUniqueI8CallbackId);
}

impl insert_unique_i_8 for super::RemoteReducers {
    fn insert_unique_i_8(&self, n: i8, data: i32) -> __anyhow::Result<()> {
        self.imp.call_reducer("insert_unique_i8", InsertUniqueI8 { n, data })
    }
    fn on_insert_unique_i_8(
        &self,
        mut callback: impl FnMut(&super::EventContext, &i8, &i32) + Send + 'static,
    ) -> InsertUniqueI8CallbackId {
        InsertUniqueI8CallbackId(self.imp.on_reducer::<InsertUniqueI8>(
            "insert_unique_i8",
            Box::new(move |ctx: &super::EventContext, args: &InsertUniqueI8| callback(ctx, &args.n, &args.data)),
        ))
    }
    fn remove_on_insert_unique_i_8(&self, callback: InsertUniqueI8CallbackId) {
        self.imp
            .remove_on_reducer::<InsertUniqueI8>("insert_unique_i8", callback.0)
    }
}
