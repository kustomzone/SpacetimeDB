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
pub struct UpdatePkU64 {
    pub n: u64,
    pub data: i32,
}

impl __sdk::spacetime_module::InModule for UpdatePkU64 {
    type Module = super::RemoteModule;
}

pub struct UpdatePkU64CallbackId(__sdk::callbacks::CallbackId);

#[allow(non_camel_case_types)]
pub trait update_pk_u_64 {
    fn update_pk_u_64(&self, n: u64, data: i32) -> __anyhow::Result<()>;
    fn on_update_pk_u_64(
        &self,
        callback: impl FnMut(&super::EventContext, &u64, &i32) + Send + 'static,
    ) -> UpdatePkU64CallbackId;
    fn remove_on_update_pk_u_64(&self, callback: UpdatePkU64CallbackId);
}

impl update_pk_u_64 for super::RemoteReducers {
    fn update_pk_u_64(&self, n: u64, data: i32) -> __anyhow::Result<()> {
        self.imp.call_reducer("update_pk_u64", UpdatePkU64 { n, data })
    }
    fn on_update_pk_u_64(
        &self,
        mut callback: impl FnMut(&super::EventContext, &u64, &i32) + Send + 'static,
    ) -> UpdatePkU64CallbackId {
        UpdatePkU64CallbackId(self.imp.on_reducer::<UpdatePkU64>(
            "update_pk_u64",
            Box::new(move |ctx: &super::EventContext, args: &UpdatePkU64| callback(ctx, &args.n, &args.data)),
        ))
    }
    fn remove_on_update_pk_u_64(&self, callback: UpdatePkU64CallbackId) {
        self.imp.remove_on_reducer::<UpdatePkU64>("update_pk_u64", callback.0)
    }
}
