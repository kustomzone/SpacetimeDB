// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN RUST INSTEAD.

#![allow(unused, clippy::all)]
use spacetimedb_sdk::__codegen::{self as __sdk, __lib, __sats, __ws};

#[derive(__lib::ser::Serialize, __lib::de::Deserialize, Clone, PartialEq, Debug)]
#[sats(crate = __lib)]
pub(super) struct InsertVecU8Args {
    pub n: Vec<u8>,
}

impl From<InsertVecU8Args> for super::Reducer {
    fn from(args: InsertVecU8Args) -> Self {
        Self::InsertVecU8 { n: args.n }
    }
}

impl __sdk::InModule for InsertVecU8Args {
    type Module = super::RemoteModule;
}

pub struct InsertVecU8CallbackId(__sdk::CallbackId);

#[allow(non_camel_case_types)]
/// Extension trait for access to the reducer `insert_vec_u8`.
///
/// Implemented for [`super::RemoteReducers`].
pub trait insert_vec_u_8 {
    /// Request that the remote module invoke the reducer `insert_vec_u8` to run as soon as possible.
    ///
    /// This method returns immediately, and errors only if we are unable to send the request.
    /// The reducer will run asynchronously in the future,
    ///  and its status can be observed by listening for [`Self::on_insert_vec_u_8`] callbacks.
    fn insert_vec_u_8(&self, n: Vec<u8>) -> __sdk::Result<()>;
    /// Register a callback to run whenever we are notified of an invocation of the reducer `insert_vec_u8`.
    ///
    /// Callbacks should inspect the [`__sdk::ReducerEvent`] contained in the [`super::ReducerEventContext`]
    /// to determine the reducer's status.
    ///
    /// The returned [`InsertVecU8CallbackId`] can be passed to [`Self::remove_on_insert_vec_u_8`]
    /// to cancel the callback.
    fn on_insert_vec_u_8(
        &self,
        callback: impl FnMut(&super::ReducerEventContext, &Vec<u8>) + Send + 'static,
    ) -> InsertVecU8CallbackId;
    /// Cancel a callback previously registered by [`Self::on_insert_vec_u_8`],
    /// causing it not to run in the future.
    fn remove_on_insert_vec_u_8(&self, callback: InsertVecU8CallbackId);
}

impl insert_vec_u_8 for super::RemoteReducers {
    fn insert_vec_u_8(&self, n: Vec<u8>) -> __sdk::Result<()> {
        self.imp.call_reducer("insert_vec_u8", InsertVecU8Args { n })
    }
    fn on_insert_vec_u_8(
        &self,
        mut callback: impl FnMut(&super::ReducerEventContext, &Vec<u8>) + Send + 'static,
    ) -> InsertVecU8CallbackId {
        InsertVecU8CallbackId(self.imp.on_reducer(
            "insert_vec_u8",
            Box::new(move |ctx: &super::ReducerEventContext| {
                let super::ReducerEventContext {
                    event:
                        __sdk::ReducerEvent {
                            reducer: super::Reducer::InsertVecU8 { n },
                            ..
                        },
                    ..
                } = ctx
                else {
                    unreachable!()
                };
                callback(ctx, n)
            }),
        ))
    }
    fn remove_on_insert_vec_u_8(&self, callback: InsertVecU8CallbackId) {
        self.imp.remove_on_reducer("insert_vec_u8", callback.0)
    }
}

#[allow(non_camel_case_types)]
#[doc(hidden)]
/// Extension trait for setting the call-flags for the reducer `insert_vec_u8`.
///
/// Implemented for [`super::SetReducerFlags`].
///
/// This type is currently unstable and may be removed without a major version bump.
pub trait set_flags_for_insert_vec_u_8 {
    /// Set the call-reducer flags for the reducer `insert_vec_u8` to `flags`.
    ///
    /// This type is currently unstable and may be removed without a major version bump.
    fn insert_vec_u_8(&self, flags: __ws::CallReducerFlags);
}

impl set_flags_for_insert_vec_u_8 for super::SetReducerFlags {
    fn insert_vec_u_8(&self, flags: __ws::CallReducerFlags) {
        self.imp.set_call_reducer_flags("insert_vec_u8", flags);
    }
}
