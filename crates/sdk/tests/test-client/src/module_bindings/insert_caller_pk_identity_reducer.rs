// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN RUST INSTEAD.

#![allow(unused, clippy::all)]
use spacetimedb_sdk::__codegen::{self as __sdk, __lib, __sats, __ws};

#[derive(__lib::ser::Serialize, __lib::de::Deserialize, Clone, PartialEq, Debug)]
#[sats(crate = __lib)]
pub(super) struct InsertCallerPkIdentityArgs {
    pub data: i32,
}

impl From<InsertCallerPkIdentityArgs> for super::Reducer {
    fn from(args: InsertCallerPkIdentityArgs) -> Self {
        Self::InsertCallerPkIdentity { data: args.data }
    }
}

impl __sdk::InModule for InsertCallerPkIdentityArgs {
    type Module = super::RemoteModule;
}

pub struct InsertCallerPkIdentityCallbackId(__sdk::CallbackId);

#[allow(non_camel_case_types)]
/// Extension trait for access to the reducer `insert_caller_pk_identity`.
///
/// Implemented for [`super::RemoteReducers`].
pub trait insert_caller_pk_identity {
    /// Request that the remote module invoke the reducer `insert_caller_pk_identity` to run as soon as possible.
    ///
    /// This method returns immediately, and errors only if we are unable to send the request.
    /// The reducer will run asynchronously in the future,
    ///  and its status can be observed by listening for [`Self::on_insert_caller_pk_identity`] callbacks.
    fn insert_caller_pk_identity(&self, data: i32) -> __sdk::Result<()>;
    /// Register a callback to run whenever we are notified of an invocation of the reducer `insert_caller_pk_identity`.
    ///
    /// Callbacks should inspect the [`__sdk::ReducerEvent`] contained in the [`super::ReducerEventContext`]
    /// to determine the reducer's status.
    ///
    /// The returned [`InsertCallerPkIdentityCallbackId`] can be passed to [`Self::remove_on_insert_caller_pk_identity`]
    /// to cancel the callback.
    fn on_insert_caller_pk_identity(
        &self,
        callback: impl FnMut(&super::ReducerEventContext, &i32) + Send + 'static,
    ) -> InsertCallerPkIdentityCallbackId;
    /// Cancel a callback previously registered by [`Self::on_insert_caller_pk_identity`],
    /// causing it not to run in the future.
    fn remove_on_insert_caller_pk_identity(&self, callback: InsertCallerPkIdentityCallbackId);
}

impl insert_caller_pk_identity for super::RemoteReducers {
    fn insert_caller_pk_identity(&self, data: i32) -> __sdk::Result<()> {
        self.imp
            .call_reducer("insert_caller_pk_identity", InsertCallerPkIdentityArgs { data })
    }
    fn on_insert_caller_pk_identity(
        &self,
        mut callback: impl FnMut(&super::ReducerEventContext, &i32) + Send + 'static,
    ) -> InsertCallerPkIdentityCallbackId {
        InsertCallerPkIdentityCallbackId(self.imp.on_reducer(
            "insert_caller_pk_identity",
            Box::new(move |ctx: &super::ReducerEventContext| {
                let super::ReducerEventContext {
                    event:
                        __sdk::ReducerEvent {
                            reducer: super::Reducer::InsertCallerPkIdentity { data },
                            ..
                        },
                    ..
                } = ctx
                else {
                    unreachable!()
                };
                callback(ctx, data)
            }),
        ))
    }
    fn remove_on_insert_caller_pk_identity(&self, callback: InsertCallerPkIdentityCallbackId) {
        self.imp.remove_on_reducer("insert_caller_pk_identity", callback.0)
    }
}

#[allow(non_camel_case_types)]
#[doc(hidden)]
/// Extension trait for setting the call-flags for the reducer `insert_caller_pk_identity`.
///
/// Implemented for [`super::SetReducerFlags`].
///
/// This type is currently unstable and may be removed without a major version bump.
pub trait set_flags_for_insert_caller_pk_identity {
    /// Set the call-reducer flags for the reducer `insert_caller_pk_identity` to `flags`.
    ///
    /// This type is currently unstable and may be removed without a major version bump.
    fn insert_caller_pk_identity(&self, flags: __ws::CallReducerFlags);
}

impl set_flags_for_insert_caller_pk_identity for super::SetReducerFlags {
    fn insert_caller_pk_identity(&self, flags: __ws::CallReducerFlags) {
        self.imp.set_call_reducer_flags("insert_caller_pk_identity", flags);
    }
}
