// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN RUST INSTEAD.

#![allow(unused, clippy::all)]
use spacetimedb_sdk::__codegen::{self as __sdk, __lib, __sats, __ws};

#[derive(__lib::ser::Serialize, __lib::de::Deserialize, Clone, PartialEq, Debug)]
#[sats(crate = __lib)]
pub(super) struct InsertUniqueU32Args {
    pub n: u32,
    pub data: i32,
}

impl From<InsertUniqueU32Args> for super::Reducer {
    fn from(args: InsertUniqueU32Args) -> Self {
        Self::InsertUniqueU32 {
            n: args.n,
            data: args.data,
        }
    }
}

impl __sdk::InModule for InsertUniqueU32Args {
    type Module = super::RemoteModule;
}

pub struct InsertUniqueU32CallbackId(__sdk::CallbackId);

#[allow(non_camel_case_types)]
/// Extension trait for access to the reducer `insert_unique_u32`.
///
/// Implemented for [`super::RemoteReducers`].
pub trait insert_unique_u_32 {
    /// Request that the remote module invoke the reducer `insert_unique_u32` to run as soon as possible.
    ///
    /// This method returns immediately, and errors only if we are unable to send the request.
    /// The reducer will run asynchronously in the future,
    ///  and its status can be observed by listening for [`Self::on_insert_unique_u_32`] callbacks.
    fn insert_unique_u_32(&self, n: u32, data: i32) -> __sdk::Result<()>;
    /// Register a callback to run whenever we are notified of an invocation of the reducer `insert_unique_u32`.
    ///
    /// Callbacks should inspect the [`__sdk::ReducerEvent`] contained in the [`super::ReducerEventContext`]
    /// to determine the reducer's status.
    ///
    /// The returned [`InsertUniqueU32CallbackId`] can be passed to [`Self::remove_on_insert_unique_u_32`]
    /// to cancel the callback.
    fn on_insert_unique_u_32(
        &self,
        callback: impl FnMut(&super::ReducerEventContext, &u32, &i32) + Send + 'static,
    ) -> InsertUniqueU32CallbackId;
    /// Cancel a callback previously registered by [`Self::on_insert_unique_u_32`],
    /// causing it not to run in the future.
    fn remove_on_insert_unique_u_32(&self, callback: InsertUniqueU32CallbackId);
}

impl insert_unique_u_32 for super::RemoteReducers {
    fn insert_unique_u_32(&self, n: u32, data: i32) -> __sdk::Result<()> {
        self.imp
            .call_reducer("insert_unique_u32", InsertUniqueU32Args { n, data })
    }
    fn on_insert_unique_u_32(
        &self,
        mut callback: impl FnMut(&super::ReducerEventContext, &u32, &i32) + Send + 'static,
    ) -> InsertUniqueU32CallbackId {
        InsertUniqueU32CallbackId(self.imp.on_reducer(
            "insert_unique_u32",
            Box::new(move |ctx: &super::ReducerEventContext| {
                let super::ReducerEventContext {
                    event:
                        __sdk::ReducerEvent {
                            reducer: super::Reducer::InsertUniqueU32 { n, data },
                            ..
                        },
                    ..
                } = ctx
                else {
                    unreachable!()
                };
                callback(ctx, n, data)
            }),
        ))
    }
    fn remove_on_insert_unique_u_32(&self, callback: InsertUniqueU32CallbackId) {
        self.imp.remove_on_reducer("insert_unique_u32", callback.0)
    }
}

#[allow(non_camel_case_types)]
#[doc(hidden)]
/// Extension trait for setting the call-flags for the reducer `insert_unique_u32`.
///
/// Implemented for [`super::SetReducerFlags`].
///
/// This type is currently unstable and may be removed without a major version bump.
pub trait set_flags_for_insert_unique_u_32 {
    /// Set the call-reducer flags for the reducer `insert_unique_u32` to `flags`.
    ///
    /// This type is currently unstable and may be removed without a major version bump.
    fn insert_unique_u_32(&self, flags: __ws::CallReducerFlags);
}

impl set_flags_for_insert_unique_u_32 for super::SetReducerFlags {
    fn insert_unique_u_32(&self, flags: __ws::CallReducerFlags) {
        self.imp.set_call_reducer_flags("insert_unique_u32", flags);
    }
}
