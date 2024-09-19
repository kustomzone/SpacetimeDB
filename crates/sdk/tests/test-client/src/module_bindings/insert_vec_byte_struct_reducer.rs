// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN RUST INSTEAD.

#![allow(unused)]
use spacetimedb_sdk::{
    self as __sdk,
    anyhow::{self as __anyhow, Context as _},
    lib as __lib, sats as __sats, ws_messages as __ws,
};

use super::byte_struct_type::ByteStruct;

#[derive(__lib::ser::Serialize, __lib::de::Deserialize, Clone, PartialEq, Debug)]
#[sats(crate = __lib)]
pub struct InsertVecByteStruct {
    pub s: Vec<ByteStruct>,
}

impl __sdk::spacetime_module::InModule for InsertVecByteStruct {
    type Module = super::RemoteModule;
}

pub struct InsertVecByteStructCallbackId(__sdk::callbacks::CallbackId);

#[allow(non_camel_case_types)]
pub trait insert_vec_byte_struct {
    fn insert_vec_byte_struct(&self, s: Vec<ByteStruct>) -> __anyhow::Result<()>;
    fn on_insert_vec_byte_struct(
        &self,
        callback: impl FnMut(&super::EventContext, &Vec<ByteStruct>) + Send + 'static,
    ) -> InsertVecByteStructCallbackId;
    fn remove_on_insert_vec_byte_struct(&self, callback: InsertVecByteStructCallbackId);
}

impl insert_vec_byte_struct for super::RemoteReducers {
    fn insert_vec_byte_struct(&self, s: Vec<ByteStruct>) -> __anyhow::Result<()> {
        self.imp
            .call_reducer("insert_vec_byte_struct", InsertVecByteStruct { s })
    }
    fn on_insert_vec_byte_struct(
        &self,
        mut callback: impl FnMut(&super::EventContext, &Vec<ByteStruct>) + Send + 'static,
    ) -> InsertVecByteStructCallbackId {
        InsertVecByteStructCallbackId(self.imp.on_reducer::<InsertVecByteStruct>(
            "insert_vec_byte_struct",
            Box::new(move |ctx: &super::EventContext, args: &InsertVecByteStruct| callback(ctx, &args.s)),
        ))
    }
    fn remove_on_insert_vec_byte_struct(&self, callback: InsertVecByteStructCallbackId) {
        self.imp
            .remove_on_reducer::<InsertVecByteStruct>("insert_vec_byte_struct", callback.0)
    }
}
