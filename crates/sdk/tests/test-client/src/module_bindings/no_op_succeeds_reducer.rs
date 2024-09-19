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
pub struct NoOpSucceeds {}

impl __sdk::spacetime_module::InModule for NoOpSucceeds {
    type Module = super::RemoteModule;
}

pub struct NoOpSucceedsCallbackId(__sdk::callbacks::CallbackId);

#[allow(non_camel_case_types)]
pub trait no_op_succeeds {
    fn no_op_succeeds(&self) -> __anyhow::Result<()>;
    fn on_no_op_succeeds(&self, callback: impl FnMut(&super::EventContext) + Send + 'static) -> NoOpSucceedsCallbackId;
    fn remove_on_no_op_succeeds(&self, callback: NoOpSucceedsCallbackId);
}

impl no_op_succeeds for super::RemoteReducers {
    fn no_op_succeeds(&self) -> __anyhow::Result<()> {
        self.imp.call_reducer("no_op_succeeds", NoOpSucceeds {})
    }
    fn on_no_op_succeeds(
        &self,
        mut callback: impl FnMut(&super::EventContext) + Send + 'static,
    ) -> NoOpSucceedsCallbackId {
        NoOpSucceedsCallbackId(self.imp.on_reducer::<NoOpSucceeds>(
            "no_op_succeeds",
            Box::new(move |ctx: &super::EventContext, args: &NoOpSucceeds| callback(ctx)),
        ))
    }
    fn remove_on_no_op_succeeds(&self, callback: NoOpSucceedsCallbackId) {
        self.imp.remove_on_reducer::<NoOpSucceeds>("no_op_succeeds", callback.0)
    }
}
