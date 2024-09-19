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
pub struct InsertCallerOneIdentity {}

impl __sdk::spacetime_module::InModule for InsertCallerOneIdentity {
    type Module = super::RemoteModule;
}

pub struct InsertCallerOneIdentityCallbackId(__sdk::callbacks::CallbackId);

#[allow(non_camel_case_types)]
pub trait insert_caller_one_identity {
    fn insert_caller_one_identity(&self) -> __anyhow::Result<()>;
    fn on_insert_caller_one_identity(
        &self,
        callback: impl FnMut(&super::EventContext) + Send + 'static,
    ) -> InsertCallerOneIdentityCallbackId;
    fn remove_on_insert_caller_one_identity(&self, callback: InsertCallerOneIdentityCallbackId);
}

impl insert_caller_one_identity for super::RemoteReducers {
    fn insert_caller_one_identity(&self) -> __anyhow::Result<()> {
        self.imp
            .call_reducer("insert_caller_one_identity", InsertCallerOneIdentity {})
    }
    fn on_insert_caller_one_identity(
        &self,
        mut callback: impl FnMut(&super::EventContext) + Send + 'static,
    ) -> InsertCallerOneIdentityCallbackId {
        InsertCallerOneIdentityCallbackId(self.imp.on_reducer::<InsertCallerOneIdentity>(
            "insert_caller_one_identity",
            Box::new(move |ctx: &super::EventContext, args: &InsertCallerOneIdentity| callback(ctx)),
        ))
    }
    fn remove_on_insert_caller_one_identity(&self, callback: InsertCallerOneIdentityCallbackId) {
        self.imp
            .remove_on_reducer::<InsertCallerOneIdentity>("insert_caller_one_identity", callback.0)
    }
}
