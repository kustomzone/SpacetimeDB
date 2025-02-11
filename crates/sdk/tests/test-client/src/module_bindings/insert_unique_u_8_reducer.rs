// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN YOUR MODULE SOURCE CODE INSTEAD.

#![allow(unused, clippy::all)]
use spacetimedb_sdk::__codegen::{self as __sdk, __lib, __sats, __ws};

#[derive(__lib::ser::Serialize, __lib::de::Deserialize, Clone, PartialEq, Debug)]
#[sats(crate = __lib)]
pub(super) struct InsertUniqueU8Args {
    pub n: u8,
    pub data: i32,
}

impl From<InsertUniqueU8Args> for super::Reducer {
    fn from(args: InsertUniqueU8Args) -> Self {
        Self::InsertUniqueU8 {
            n: args.n,
            data: args.data,
        }
    }
}

impl __sdk::InModule for InsertUniqueU8Args {
    type Module = super::RemoteModule;
}

pub struct InsertUniqueU8CallbackId(__sdk::CallbackId);

#[allow(non_camel_case_types)]
/// Extension trait for access to the reducer `insert_unique_u8`.
///
/// Implemented for [`super::RemoteReducers`].
pub trait insert_unique_u_8 {
    /// Request that the remote module invoke the reducer `insert_unique_u8` to run as soon as possible.
    ///
    /// This method returns immediately, and errors only if we are unable to send the request.
    /// The reducer will run asynchronously in the future,
    ///  and its status can be observed by listening for [`Self::on_insert_unique_u_8`] callbacks.
    fn insert_unique_u_8(&self, n: u8, data: i32) -> __sdk::Result<()>;
    /// Register a callback to run whenever we are notified of an invocation of the reducer `insert_unique_u8`.
    ///
    /// Callbacks should inspect the [`__sdk::ReducerEvent`] contained in the [`super::ReducerEventContext`]
    /// to determine the reducer's status.
    ///
    /// The returned [`InsertUniqueU8CallbackId`] can be passed to [`Self::remove_on_insert_unique_u_8`]
    /// to cancel the callback.
    fn on_insert_unique_u_8(
        &self,
        callback: impl FnMut(&super::ReducerEventContext, &u8, &i32) + Send + 'static,
    ) -> InsertUniqueU8CallbackId;
    /// Cancel a callback previously registered by [`Self::on_insert_unique_u_8`],
    /// causing it not to run in the future.
    fn remove_on_insert_unique_u_8(&self, callback: InsertUniqueU8CallbackId);
}

impl insert_unique_u_8 for super::RemoteReducers {
    fn insert_unique_u_8(&self, n: u8, data: i32) -> __sdk::Result<()> {
        self.imp
            .call_reducer("insert_unique_u8", InsertUniqueU8Args { n, data })
    }
    fn on_insert_unique_u_8(
        &self,
        mut callback: impl FnMut(&super::ReducerEventContext, &u8, &i32) + Send + 'static,
    ) -> InsertUniqueU8CallbackId {
        InsertUniqueU8CallbackId(self.imp.on_reducer(
            "insert_unique_u8",
            Box::new(move |ctx: &super::ReducerEventContext| {
                let super::ReducerEventContext {
                    event:
                        __sdk::ReducerEvent {
                            reducer: super::Reducer::InsertUniqueU8 { n, data },
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
    fn remove_on_insert_unique_u_8(&self, callback: InsertUniqueU8CallbackId) {
        self.imp.remove_on_reducer("insert_unique_u8", callback.0)
    }
}

#[allow(non_camel_case_types)]
#[doc(hidden)]
/// Extension trait for setting the call-flags for the reducer `insert_unique_u8`.
///
/// Implemented for [`super::SetReducerFlags`].
///
/// This type is currently unstable and may be removed without a major version bump.
pub trait set_flags_for_insert_unique_u_8 {
    /// Set the call-reducer flags for the reducer `insert_unique_u8` to `flags`.
    ///
    /// This type is currently unstable and may be removed without a major version bump.
    fn insert_unique_u_8(&self, flags: __ws::CallReducerFlags);
}

impl set_flags_for_insert_unique_u_8 for super::SetReducerFlags {
    fn insert_unique_u_8(&self, flags: __ws::CallReducerFlags) {
        self.imp.set_call_reducer_flags("insert_unique_u8", flags);
    }
}
