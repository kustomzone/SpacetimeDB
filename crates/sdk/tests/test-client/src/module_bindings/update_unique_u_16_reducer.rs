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
pub struct UpdateUniqueU16 {
    pub n: u16,
    pub data: i32,
}

impl __sdk::spacetime_module::InModule for UpdateUniqueU16 {
    type Module = super::RemoteModule;
}

pub struct UpdateUniqueU16CallbackId(__sdk::callbacks::CallbackId);

#[allow(non_camel_case_types)]
pub trait update_unique_u_16 {
    fn update_unique_u_16(&self, n: u16, data: i32) -> __anyhow::Result<()>;
    fn on_update_unique_u_16(
        &self,
        callback: impl FnMut(&super::EventContext, &u16, &i32) + Send + 'static,
    ) -> UpdateUniqueU16CallbackId;
    fn remove_on_update_unique_u_16(&self, callback: UpdateUniqueU16CallbackId);
}

impl update_unique_u_16 for super::RemoteReducers {
    fn update_unique_u_16(&self, n: u16, data: i32) -> __anyhow::Result<()> {
        self.imp.call_reducer("update_unique_u16", UpdateUniqueU16 { n, data })
    }
    fn on_update_unique_u_16(
        &self,
        mut callback: impl FnMut(&super::EventContext, &u16, &i32) + Send + 'static,
    ) -> UpdateUniqueU16CallbackId {
        UpdateUniqueU16CallbackId(self.imp.on_reducer::<UpdateUniqueU16>(
            "update_unique_u16",
            Box::new(move |ctx: &super::EventContext, args: &UpdateUniqueU16| callback(ctx, &args.n, &args.data)),
        ))
    }
    fn remove_on_update_unique_u_16(&self, callback: UpdateUniqueU16CallbackId) {
        self.imp
            .remove_on_reducer::<UpdateUniqueU16>("update_unique_u16", callback.0)
    }
}
