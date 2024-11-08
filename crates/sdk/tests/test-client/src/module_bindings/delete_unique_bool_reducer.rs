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
pub struct DeleteUniqueBool {
    pub b: bool,
}

impl __sdk::spacetime_module::InModule for DeleteUniqueBool {
    type Module = super::RemoteModule;
}

pub struct DeleteUniqueBoolCallbackId(__sdk::callbacks::CallbackId);

#[allow(non_camel_case_types)]
/// Extension trait for access to the reducer `delete_unique_bool`.
///
/// Implemented for [`super::RemoteReducers`].
pub trait delete_unique_bool {
    /// Request that the remote module invoke the reducer `delete_unique_bool` to run as soon as possible.
    ///
    /// This method returns immediately, and errors only if we are unable to send the request.
    /// The reducer will run asynchronously in the future,
    ///  and its status can be observed by listening for [`Self::on_delete_unique_bool`] callbacks.
    fn delete_unique_bool(&self, b: bool) -> __anyhow::Result<()>;
    /// Register a callback to run whenever we are notified of an invocation of the reducer `delete_unique_bool`.
    ///
    /// The [`super::EventContext`] passed to the `callback`
    /// will always have [`__sdk::Event::Reducer`] as its `event`,
    /// but it may or may not have terminated successfully and been committed.
    /// Callbacks should inspect the [`__sdk::ReducerEvent`] contained in the [`super::EventContext`]
    /// to determine the reducer's status.
    ///
    /// The returned [`DeleteUniqueBoolCallbackId`] can be passed to [`Self::remove_on_delete_unique_bool`]
    /// to cancel the callback.
    fn on_delete_unique_bool(
        &self,
        callback: impl FnMut(&super::EventContext, &bool) + Send + 'static,
    ) -> DeleteUniqueBoolCallbackId;
    /// Cancel a callback previously registered by [`Self::on_delete_unique_bool`],
    /// causing it not to run in the future.
    fn remove_on_delete_unique_bool(&self, callback: DeleteUniqueBoolCallbackId);
}

impl delete_unique_bool for super::RemoteReducers {
    fn delete_unique_bool(&self, b: bool) -> __anyhow::Result<()> {
        self.imp.call_reducer("delete_unique_bool", DeleteUniqueBool { b })
    }
    fn on_delete_unique_bool(
        &self,
        mut callback: impl FnMut(&super::EventContext, &bool) + Send + 'static,
    ) -> DeleteUniqueBoolCallbackId {
        DeleteUniqueBoolCallbackId(self.imp.on_reducer::<DeleteUniqueBool>(
            "delete_unique_bool",
            Box::new(move |ctx: &super::EventContext, args: &DeleteUniqueBool| callback(ctx, &args.b)),
        ))
    }
    fn remove_on_delete_unique_bool(&self, callback: DeleteUniqueBoolCallbackId) {
        self.imp
            .remove_on_reducer::<DeleteUniqueBool>("delete_unique_bool", callback.0)
    }
}

#[allow(non_camel_case_types)]
#[doc(hidden)]
/// Extension trait for setting the call-flags for the reducer `delete_unique_bool`.
///
/// Implemented for [`super::SetReducerFlags`].
///
/// This type is currently unstable and may be removed without a major version bump.
pub trait set_flags_for_delete_unique_bool {
    /// Set the call-reducer flags for the reducer `delete_unique_bool` to `flags`.
    ///
    /// This type is currently unstable and may be removed without a major version bump.
    fn delete_unique_bool(&self, flags: __ws::CallReducerFlags);
}

impl set_flags_for_delete_unique_bool for super::SetReducerFlags {
    fn delete_unique_bool(&self, flags: __ws::CallReducerFlags) {
        self.imp.set_call_reducer_flags("delete_unique_bool", flags);
    }
}
