// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN RUST INSTEAD.

#![allow(unused, clippy::all)]
use spacetimedb_sdk::__codegen::{self as __sdk, __lib, __sats, __ws};

#[derive(__lib::ser::Serialize, __lib::de::Deserialize, Clone, PartialEq, Debug)]
#[sats(crate = __lib)]
pub(super) struct IdentityConnectedArgs {}

impl From<IdentityConnectedArgs> for super::Reducer {
    fn from(args: IdentityConnectedArgs) -> Self {
        Self::IdentityConnected
    }
}

impl __sdk::InModule for IdentityConnectedArgs {
    type Module = super::RemoteModule;
}

pub struct IdentityConnectedCallbackId(__sdk::CallbackId);

#[allow(non_camel_case_types)]
/// Extension trait for access to the reducer `identity_connected`.
///
/// Implemented for [`super::RemoteReducers`].
pub trait identity_connected {
    /// Request that the remote module invoke the reducer `identity_connected` to run as soon as possible.
    ///
    /// This method returns immediately, and errors only if we are unable to send the request.
    /// The reducer will run asynchronously in the future,
    ///  and its status can be observed by listening for [`Self::on_identity_connected`] callbacks.
    fn identity_connected(&self) -> __sdk::Result<()>;
    /// Register a callback to run whenever we are notified of an invocation of the reducer `identity_connected`.
    ///
    /// Callbacks should inspect the [`__sdk::ReducerEvent`] contained in the [`super::ReducerEventContext`]
    /// to determine the reducer's status.
    ///
    /// The returned [`IdentityConnectedCallbackId`] can be passed to [`Self::remove_on_identity_connected`]
    /// to cancel the callback.
    fn on_identity_connected(
        &self,
        callback: impl FnMut(&super::ReducerEventContext) + Send + 'static,
    ) -> IdentityConnectedCallbackId;
    /// Cancel a callback previously registered by [`Self::on_identity_connected`],
    /// causing it not to run in the future.
    fn remove_on_identity_connected(&self, callback: IdentityConnectedCallbackId);
}

impl identity_connected for super::RemoteReducers {
    fn identity_connected(&self) -> __sdk::Result<()> {
        self.imp.call_reducer("identity_connected", IdentityConnectedArgs {})
    }
    fn on_identity_connected(
        &self,
        mut callback: impl FnMut(&super::ReducerEventContext) + Send + 'static,
    ) -> IdentityConnectedCallbackId {
        IdentityConnectedCallbackId(self.imp.on_reducer(
            "identity_connected",
            Box::new(move |ctx: &super::ReducerEventContext| {
                let super::ReducerEventContext {
                    event:
                        __sdk::ReducerEvent {
                            reducer: super::Reducer::IdentityConnected {},
                            ..
                        },
                    ..
                } = ctx
                else {
                    unreachable!()
                };
                callback(ctx)
            }),
        ))
    }
    fn remove_on_identity_connected(&self, callback: IdentityConnectedCallbackId) {
        self.imp.remove_on_reducer("identity_connected", callback.0)
    }
}

#[allow(non_camel_case_types)]
#[doc(hidden)]
/// Extension trait for setting the call-flags for the reducer `identity_connected`.
///
/// Implemented for [`super::SetReducerFlags`].
///
/// This type is currently unstable and may be removed without a major version bump.
pub trait set_flags_for_identity_connected {
    /// Set the call-reducer flags for the reducer `identity_connected` to `flags`.
    ///
    /// This type is currently unstable and may be removed without a major version bump.
    fn identity_connected(&self, flags: __ws::CallReducerFlags);
}

impl set_flags_for_identity_connected for super::SetReducerFlags {
    fn identity_connected(&self, flags: __ws::CallReducerFlags) {
        self.imp.set_call_reducer_flags("identity_connected", flags);
    }
}
