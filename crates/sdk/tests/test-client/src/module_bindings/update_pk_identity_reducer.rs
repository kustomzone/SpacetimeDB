// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN RUST INSTEAD.

#![allow(unused, clippy::all)]
use spacetimedb_sdk::__codegen::{self as __sdk, __lib, __sats, __ws};

#[derive(__lib::ser::Serialize, __lib::de::Deserialize, Clone, PartialEq, Debug)]
#[sats(crate = __lib)]
pub(super) struct UpdatePkIdentityArgs {
    pub i: __sdk::Identity,
    pub data: i32,
}

impl From<UpdatePkIdentityArgs> for super::Reducer {
    fn from(args: UpdatePkIdentityArgs) -> Self {
        Self::UpdatePkIdentity {
            i: args.i,
            data: args.data,
        }
    }
}

impl __sdk::InModule for UpdatePkIdentityArgs {
    type Module = super::RemoteModule;
}

pub struct UpdatePkIdentityCallbackId(__sdk::CallbackId);

#[allow(non_camel_case_types)]
/// Extension trait for access to the reducer `update_pk_identity`.
///
/// Implemented for [`super::RemoteReducers`].
pub trait update_pk_identity {
    /// Request that the remote module invoke the reducer `update_pk_identity` to run as soon as possible.
    ///
    /// This method returns immediately, and errors only if we are unable to send the request.
    /// The reducer will run asynchronously in the future,
    ///  and its status can be observed by listening for [`Self::on_update_pk_identity`] callbacks.
    fn update_pk_identity(&self, i: __sdk::Identity, data: i32) -> __sdk::Result<()>;
    /// Register a callback to run whenever we are notified of an invocation of the reducer `update_pk_identity`.
    ///
    /// Callbacks should inspect the [`__sdk::ReducerEvent`] contained in the [`super::ReducerEventContext`]
    /// to determine the reducer's status.
    ///
    /// The returned [`UpdatePkIdentityCallbackId`] can be passed to [`Self::remove_on_update_pk_identity`]
    /// to cancel the callback.
    fn on_update_pk_identity(
        &self,
        callback: impl FnMut(&super::ReducerEventContext, &__sdk::Identity, &i32) + Send + 'static,
    ) -> UpdatePkIdentityCallbackId;
    /// Cancel a callback previously registered by [`Self::on_update_pk_identity`],
    /// causing it not to run in the future.
    fn remove_on_update_pk_identity(&self, callback: UpdatePkIdentityCallbackId);
}

impl update_pk_identity for super::RemoteReducers {
    fn update_pk_identity(&self, i: __sdk::Identity, data: i32) -> __sdk::Result<()> {
        self.imp
            .call_reducer("update_pk_identity", UpdatePkIdentityArgs { i, data })
    }
    fn on_update_pk_identity(
        &self,
        mut callback: impl FnMut(&super::ReducerEventContext, &__sdk::Identity, &i32) + Send + 'static,
    ) -> UpdatePkIdentityCallbackId {
        UpdatePkIdentityCallbackId(self.imp.on_reducer(
            "update_pk_identity",
            Box::new(move |ctx: &super::ReducerEventContext| {
                let super::ReducerEventContext {
                    event:
                        __sdk::ReducerEvent {
                            reducer: super::Reducer::UpdatePkIdentity { i, data },
                            ..
                        },
                    ..
                } = ctx
                else {
                    unreachable!()
                };
                callback(ctx, i, data)
            }),
        ))
    }
    fn remove_on_update_pk_identity(&self, callback: UpdatePkIdentityCallbackId) {
        self.imp.remove_on_reducer("update_pk_identity", callback.0)
    }
}

#[allow(non_camel_case_types)]
#[doc(hidden)]
/// Extension trait for setting the call-flags for the reducer `update_pk_identity`.
///
/// Implemented for [`super::SetReducerFlags`].
///
/// This type is currently unstable and may be removed without a major version bump.
pub trait set_flags_for_update_pk_identity {
    /// Set the call-reducer flags for the reducer `update_pk_identity` to `flags`.
    ///
    /// This type is currently unstable and may be removed without a major version bump.
    fn update_pk_identity(&self, flags: __ws::CallReducerFlags);
}

impl set_flags_for_update_pk_identity for super::SetReducerFlags {
    fn update_pk_identity(&self, flags: __ws::CallReducerFlags) {
        self.imp.set_call_reducer_flags("update_pk_identity", flags);
    }
}
