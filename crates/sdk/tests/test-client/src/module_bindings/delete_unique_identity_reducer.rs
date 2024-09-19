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
pub struct DeleteUniqueIdentity {
    pub i: __sdk::Identity,
}

impl __sdk::spacetime_module::InModule for DeleteUniqueIdentity {
    type Module = super::RemoteModule;
}

pub struct DeleteUniqueIdentityCallbackId(__sdk::callbacks::CallbackId);

#[allow(non_camel_case_types)]
pub trait delete_unique_identity {
    fn delete_unique_identity(&self, i: __sdk::Identity) -> __anyhow::Result<()>;
    fn on_delete_unique_identity(
        &self,
        callback: impl FnMut(&super::EventContext, &__sdk::Identity) + Send + 'static,
    ) -> DeleteUniqueIdentityCallbackId;
    fn remove_on_delete_unique_identity(&self, callback: DeleteUniqueIdentityCallbackId);
}

impl delete_unique_identity for super::RemoteReducers {
    fn delete_unique_identity(&self, i: __sdk::Identity) -> __anyhow::Result<()> {
        self.imp
            .call_reducer("delete_unique_identity", DeleteUniqueIdentity { i })
    }
    fn on_delete_unique_identity(
        &self,
        mut callback: impl FnMut(&super::EventContext, &__sdk::Identity) + Send + 'static,
    ) -> DeleteUniqueIdentityCallbackId {
        DeleteUniqueIdentityCallbackId(self.imp.on_reducer::<DeleteUniqueIdentity>(
            "delete_unique_identity",
            Box::new(move |ctx: &super::EventContext, args: &DeleteUniqueIdentity| callback(ctx, &args.i)),
        ))
    }
    fn remove_on_delete_unique_identity(&self, callback: DeleteUniqueIdentityCallbackId) {
        self.imp
            .remove_on_reducer::<DeleteUniqueIdentity>("delete_unique_identity", callback.0)
    }
}
