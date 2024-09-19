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
pub struct InsertVecI8 {
    pub n: Vec<i8>,
}

impl __sdk::spacetime_module::InModule for InsertVecI8 {
    type Module = super::RemoteModule;
}

pub struct InsertVecI8CallbackId(__sdk::callbacks::CallbackId);

#[allow(non_camel_case_types)]
pub trait insert_vec_i_8 {
    fn insert_vec_i_8(&self, n: Vec<i8>) -> __anyhow::Result<()>;
    fn on_insert_vec_i_8(
        &self,
        callback: impl FnMut(&super::EventContext, &Vec<i8>) + Send + 'static,
    ) -> InsertVecI8CallbackId;
    fn remove_on_insert_vec_i_8(&self, callback: InsertVecI8CallbackId);
}

impl insert_vec_i_8 for super::RemoteReducers {
    fn insert_vec_i_8(&self, n: Vec<i8>) -> __anyhow::Result<()> {
        self.imp.call_reducer("insert_vec_i8", InsertVecI8 { n })
    }
    fn on_insert_vec_i_8(
        &self,
        mut callback: impl FnMut(&super::EventContext, &Vec<i8>) + Send + 'static,
    ) -> InsertVecI8CallbackId {
        InsertVecI8CallbackId(self.imp.on_reducer::<InsertVecI8>(
            "insert_vec_i8",
            Box::new(move |ctx: &super::EventContext, args: &InsertVecI8| callback(ctx, &args.n)),
        ))
    }
    fn remove_on_insert_vec_i_8(&self, callback: InsertVecI8CallbackId) {
        self.imp.remove_on_reducer::<InsertVecI8>("insert_vec_i8", callback.0)
    }
}
