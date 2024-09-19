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
pub struct UpdatePkU8 {
    pub n: u8,
    pub data: i32,
}

impl __sdk::spacetime_module::InModule for UpdatePkU8 {
    type Module = super::RemoteModule;
}

pub struct UpdatePkU8CallbackId(__sdk::callbacks::CallbackId);

#[allow(non_camel_case_types)]
pub trait update_pk_u_8 {
    fn update_pk_u_8(&self, n: u8, data: i32) -> __anyhow::Result<()>;
    fn on_update_pk_u_8(
        &self,
        callback: impl FnMut(&super::EventContext, &u8, &i32) + Send + 'static,
    ) -> UpdatePkU8CallbackId;
    fn remove_on_update_pk_u_8(&self, callback: UpdatePkU8CallbackId);
}

impl update_pk_u_8 for super::RemoteReducers {
    fn update_pk_u_8(&self, n: u8, data: i32) -> __anyhow::Result<()> {
        self.imp.call_reducer("update_pk_u8", UpdatePkU8 { n, data })
    }
    fn on_update_pk_u_8(
        &self,
        mut callback: impl FnMut(&super::EventContext, &u8, &i32) + Send + 'static,
    ) -> UpdatePkU8CallbackId {
        UpdatePkU8CallbackId(self.imp.on_reducer::<UpdatePkU8>(
            "update_pk_u8",
            Box::new(move |ctx: &super::EventContext, args: &UpdatePkU8| callback(ctx, &args.n, &args.data)),
        ))
    }
    fn remove_on_update_pk_u_8(&self, callback: UpdatePkU8CallbackId) {
        self.imp.remove_on_reducer::<UpdatePkU8>("update_pk_u8", callback.0)
    }
}
