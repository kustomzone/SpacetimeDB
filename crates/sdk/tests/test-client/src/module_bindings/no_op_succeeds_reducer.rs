// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN RUST INSTEAD.

#![allow(unused, clippy::all)]
use spacetimedb_sdk::__codegen::{self as __sdk, __lib, __sats, __ws};

#[derive(__lib::ser::Serialize, __lib::de::Deserialize, Clone, PartialEq, Debug)]
#[sats(crate = __lib)]
pub(super) struct NoOpSucceedsArgs {}

impl From<NoOpSucceedsArgs> for super::Reducer {
    fn from(args: NoOpSucceedsArgs) -> Self {
        Self::NoOpSucceeds
    }
}

impl __sdk::InModule for NoOpSucceedsArgs {
    type Module = super::RemoteModule;
}

pub struct NoOpSucceedsCallbackId(__sdk::CallbackId);

#[allow(non_camel_case_types)]
/// Extension trait for access to the reducer `no_op_succeeds`.
///
/// Implemented for [`super::RemoteReducers`].
pub trait no_op_succeeds {
    /// Request that the remote module invoke the reducer `no_op_succeeds` to run as soon as possible.
    ///
    /// This method returns immediately, and errors only if we are unable to send the request.
    /// The reducer will run asynchronously in the future,
    ///  and its status can be observed by listening for [`Self::on_no_op_succeeds`] callbacks.
    fn no_op_succeeds(&self) -> __sdk::Result<()>;
    /// Register a callback to run whenever we are notified of an invocation of the reducer `no_op_succeeds`.
    ///
    /// Callbacks should inspect the [`__sdk::ReducerEvent`] contained in the [`super::ReducerEventContext`]
    /// to determine the reducer's status.
    ///
    /// The returned [`NoOpSucceedsCallbackId`] can be passed to [`Self::remove_on_no_op_succeeds`]
    /// to cancel the callback.
    fn on_no_op_succeeds(
        &self,
        callback: impl FnMut(&super::ReducerEventContext) + Send + 'static,
    ) -> NoOpSucceedsCallbackId;
    /// Cancel a callback previously registered by [`Self::on_no_op_succeeds`],
    /// causing it not to run in the future.
    fn remove_on_no_op_succeeds(&self, callback: NoOpSucceedsCallbackId);
}

impl no_op_succeeds for super::RemoteReducers {
    fn no_op_succeeds(&self) -> __sdk::Result<()> {
        self.imp.call_reducer("no_op_succeeds", NoOpSucceedsArgs {})
    }
    fn on_no_op_succeeds(
        &self,
        mut callback: impl FnMut(&super::ReducerEventContext) + Send + 'static,
    ) -> NoOpSucceedsCallbackId {
        NoOpSucceedsCallbackId(self.imp.on_reducer(
            "no_op_succeeds",
            Box::new(move |ctx: &super::ReducerEventContext| {
                let super::ReducerEventContext {
                    event:
                        __sdk::ReducerEvent {
                            reducer: super::Reducer::NoOpSucceeds {},
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
    fn remove_on_no_op_succeeds(&self, callback: NoOpSucceedsCallbackId) {
        self.imp.remove_on_reducer("no_op_succeeds", callback.0)
    }
}

#[allow(non_camel_case_types)]
#[doc(hidden)]
/// Extension trait for setting the call-flags for the reducer `no_op_succeeds`.
///
/// Implemented for [`super::SetReducerFlags`].
///
/// This type is currently unstable and may be removed without a major version bump.
pub trait set_flags_for_no_op_succeeds {
    /// Set the call-reducer flags for the reducer `no_op_succeeds` to `flags`.
    ///
    /// This type is currently unstable and may be removed without a major version bump.
    fn no_op_succeeds(&self, flags: __ws::CallReducerFlags);
}

impl set_flags_for_no_op_succeeds for super::SetReducerFlags {
    fn no_op_succeeds(&self, flags: __ws::CallReducerFlags) {
        self.imp.set_call_reducer_flags("no_op_succeeds", flags);
    }
}
