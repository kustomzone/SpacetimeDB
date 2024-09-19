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
pub struct DeleteUniqueU16 {
    pub n: u16,
}

impl __sdk::spacetime_module::InModule for DeleteUniqueU16 {
    type Module = super::RemoteModule;
}

pub struct DeleteUniqueU16CallbackId(__sdk::callbacks::CallbackId);

#[allow(non_camel_case_types)]
pub trait delete_unique_u_16 {
    fn delete_unique_u_16(&self, n: u16) -> __anyhow::Result<()>;
    fn on_delete_unique_u_16(
        &self,
        callback: impl FnMut(&super::EventContext, &u16) + Send + 'static,
    ) -> DeleteUniqueU16CallbackId;
    fn remove_on_delete_unique_u_16(&self, callback: DeleteUniqueU16CallbackId);
}

impl delete_unique_u_16 for super::RemoteReducers {
    fn delete_unique_u_16(&self, n: u16) -> __anyhow::Result<()> {
        self.imp.call_reducer("delete_unique_u16", DeleteUniqueU16 { n })
    }
    fn on_delete_unique_u_16(
        &self,
        mut callback: impl FnMut(&super::EventContext, &u16) + Send + 'static,
    ) -> DeleteUniqueU16CallbackId {
        DeleteUniqueU16CallbackId(self.imp.on_reducer::<DeleteUniqueU16>(
            "delete_unique_u16",
            Box::new(move |ctx: &super::EventContext, args: &DeleteUniqueU16| callback(ctx, &args.n)),
        ))
    }
    fn remove_on_delete_unique_u_16(&self, callback: DeleteUniqueU16CallbackId) {
        self.imp
            .remove_on_reducer::<DeleteUniqueU16>("delete_unique_u16", callback.0)
    }
}
