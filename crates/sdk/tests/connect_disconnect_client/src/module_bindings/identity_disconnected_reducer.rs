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
pub struct IdentityDisconnected {}

impl __sdk::spacetime_module::InModule for IdentityDisconnected {
    type Module = super::RemoteModule;
}

pub struct IdentityDisconnectedCallbackId(__sdk::callbacks::CallbackId);

#[allow(non_camel_case_types)]
/// Extension trait for access to the reducer `__identity_disconnected__`.
///
/// Implemented for [`super::RemoteReducers`].
pub trait identity_disconnected {
    /// Request that the remote module invoke the reducer `__identity_disconnected__` to run as soon as possible.
    ///
    /// This method returns immediately, and errors only if we are unable to send the request.
    /// The reducer will run asynchronously in the future,
    ///  and its status can be observed by listening for [`Self::on_identity_disconnected`] callbacks.
    fn identity_disconnected(&self) -> __anyhow::Result<()>;
    /// Register a callback to run whenever we are notified of an invocation of the reducer `__identity_disconnected__`.
    ///
    /// The [`super::EventContext`] passed to the `callback`
    /// will always have [`__sdk::Event::Reducer`] as its `event`,
    /// but it may or may not have terminated successfully and been committed.
    /// Callbacks should inspect the [`__sdk::ReducerEvent`] contained in the [`super::EventContext`]
    /// to determine the reducer's status.
    ///
    /// The returned [`IdentityDisconnectedCallbackId`] can be passed to [`Self::remove_on_identity_disconnected`]
    /// to cancel the callback.
    fn on_identity_disconnected(
        &self,
        callback: impl FnMut(&super::EventContext) + Send + 'static,
    ) -> IdentityDisconnectedCallbackId;
    /// Cancel a callback previously registered by [`Self::on_identity_disconnected`],
    /// causing it not to run in the future.
    fn remove_on_identity_disconnected(&self, callback: IdentityDisconnectedCallbackId);
}

impl identity_disconnected for super::RemoteReducers {
    fn identity_disconnected(&self) -> __anyhow::Result<()> {
        self.imp
            .call_reducer("__identity_disconnected__", IdentityDisconnected {})
    }
    fn on_identity_disconnected(
        &self,
        mut callback: impl FnMut(&super::EventContext) + Send + 'static,
    ) -> IdentityDisconnectedCallbackId {
        IdentityDisconnectedCallbackId(self.imp.on_reducer::<IdentityDisconnected>(
            "__identity_disconnected__",
            Box::new(move |ctx: &super::EventContext, args: &IdentityDisconnected| callback(ctx)),
        ))
    }
    fn remove_on_identity_disconnected(&self, callback: IdentityDisconnectedCallbackId) {
        self.imp
            .remove_on_reducer::<IdentityDisconnected>("__identity_disconnected__", callback.0)
    }
}

#[allow(non_camel_case_types)]
#[doc(hidden)]
/// Extension trait for setting the call-flags for the reducer `__identity_disconnected__`.
///
/// Implemented for [`super::SetReducerFlags`].
///
/// This type is currently unstable and may be removed without a major version bump.
pub trait set_flags_for_identity_disconnected {
    /// Set the call-reducer flags for the reducer `__identity_disconnected__` to `flags`.
    ///
    /// This type is currently unstable and may be removed without a major version bump.
    fn identity_disconnected(&self, flags: __ws::CallReducerFlags);
}

impl set_flags_for_identity_disconnected for super::SetReducerFlags {
    fn identity_disconnected(&self, flags: __ws::CallReducerFlags) {
        self.imp.set_call_reducer_flags("__identity_disconnected__", flags);
    }
}
