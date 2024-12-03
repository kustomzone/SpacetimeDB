// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN RUST INSTEAD.

#![allow(unused)]
use spacetimedb_sdk::__codegen::{
    self as __sdk, __lib, __sats, __ws,
    anyhow::{self as __anyhow, Context as _},
};

#[derive(__lib::ser::Serialize, __lib::de::Deserialize, Clone, PartialEq, Debug)]
#[sats(crate = __lib)]
pub(super) struct InsertUniqueIdentityArgs {
    pub i: __sdk::Identity,
    pub data: i32,
}

impl From<InsertUniqueIdentityArgs> for super::Reducer {
    fn from(args: InsertUniqueIdentityArgs) -> Self {
        Self::InsertUniqueIdentity {
            i: args.i,
            data: args.data,
        }
    }
}

impl __sdk::InModule for InsertUniqueIdentityArgs {
    type Module = super::RemoteModule;
}

pub struct InsertUniqueIdentityCallbackId(__sdk::CallbackId);

#[allow(non_camel_case_types)]
/// Extension trait for access to the reducer `insert_unique_identity`.
///
/// Implemented for [`super::RemoteReducers`].
pub trait insert_unique_identity {
    /// Request that the remote module invoke the reducer `insert_unique_identity` to run as soon as possible.
    ///
    /// This method returns immediately, and errors only if we are unable to send the request.
    /// The reducer will run asynchronously in the future,
    ///  and its status can be observed by listening for [`Self::on_insert_unique_identity`] callbacks.
    fn insert_unique_identity(&self, i: __sdk::Identity, data: i32) -> __anyhow::Result<()>;
    /// Register a callback to run whenever we are notified of an invocation of the reducer `insert_unique_identity`.
    ///
    /// The [`super::EventContext`] passed to the `callback`
    /// will always have [`__sdk::Event::Reducer`] as its `event`,
    /// but it may or may not have terminated successfully and been committed.
    /// Callbacks should inspect the [`__sdk::ReducerEvent`] contained in the [`super::EventContext`]
    /// to determine the reducer's status.
    ///
    /// The returned [`InsertUniqueIdentityCallbackId`] can be passed to [`Self::remove_on_insert_unique_identity`]
    /// to cancel the callback.
    fn on_insert_unique_identity(
        &self,
        callback: impl FnMut(&super::EventContext, &__sdk::Identity, &i32) + Send + 'static,
    ) -> InsertUniqueIdentityCallbackId;
    /// Cancel a callback previously registered by [`Self::on_insert_unique_identity`],
    /// causing it not to run in the future.
    fn remove_on_insert_unique_identity(&self, callback: InsertUniqueIdentityCallbackId);
}

impl insert_unique_identity for super::RemoteReducers {
    fn insert_unique_identity(&self, i: __sdk::Identity, data: i32) -> __anyhow::Result<()> {
        self.imp
            .call_reducer("insert_unique_identity", InsertUniqueIdentityArgs { i, data })
    }
    fn on_insert_unique_identity(
        &self,
        mut callback: impl FnMut(&super::EventContext, &__sdk::Identity, &i32) + Send + 'static,
    ) -> InsertUniqueIdentityCallbackId {
        InsertUniqueIdentityCallbackId(self.imp.on_reducer(
            "insert_unique_identity",
            Box::new(move |ctx: &super::EventContext| {
                let super::EventContext {
                    event:
                        __sdk::Event::Reducer(__sdk::ReducerEvent {
                            reducer: super::Reducer::InsertUniqueIdentity { i, data },
                            ..
                        }),
                    ..
                } = ctx
                else {
                    unreachable!()
                };
                callback(ctx, i, data)
            }),
        ))
    }
    fn remove_on_insert_unique_identity(&self, callback: InsertUniqueIdentityCallbackId) {
        self.imp.remove_on_reducer("insert_unique_identity", callback.0)
    }
}

#[allow(non_camel_case_types)]
#[doc(hidden)]
/// Extension trait for setting the call-flags for the reducer `insert_unique_identity`.
///
/// Implemented for [`super::SetReducerFlags`].
///
/// This type is currently unstable and may be removed without a major version bump.
pub trait set_flags_for_insert_unique_identity {
    /// Set the call-reducer flags for the reducer `insert_unique_identity` to `flags`.
    ///
    /// This type is currently unstable and may be removed without a major version bump.
    fn insert_unique_identity(&self, flags: __ws::CallReducerFlags);
}

impl set_flags_for_insert_unique_identity for super::SetReducerFlags {
    fn insert_unique_identity(&self, flags: __ws::CallReducerFlags) {
        self.imp.set_call_reducer_flags("insert_unique_identity", flags);
    }
}
