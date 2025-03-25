// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN YOUR MODULE SOURCE CODE INSTEAD.

#![allow(unused, clippy::all)]
use spacetimedb_sdk::__codegen::{self as __sdk, __lib, __sats, __ws};

use super::simple_enum_type::SimpleEnum;

#[derive(__lib::ser::Serialize, __lib::de::Deserialize, Clone, PartialEq, Debug)]
#[sats(crate = __lib)]
pub(super) struct InsertIntoIndexedSimpleEnumArgs {
    pub n: SimpleEnum,
}

impl From<InsertIntoIndexedSimpleEnumArgs> for super::Reducer {
    fn from(args: InsertIntoIndexedSimpleEnumArgs) -> Self {
        Self::InsertIntoIndexedSimpleEnum { n: args.n }
    }
}

impl __sdk::InModule for InsertIntoIndexedSimpleEnumArgs {
    type Module = super::RemoteModule;
}

pub struct InsertIntoIndexedSimpleEnumCallbackId(__sdk::CallbackId);

#[allow(non_camel_case_types)]
/// Extension trait for access to the reducer `insert_into_indexed_simple_enum`.
///
/// Implemented for [`super::RemoteReducers`].
pub trait insert_into_indexed_simple_enum {
    /// Request that the remote module invoke the reducer `insert_into_indexed_simple_enum` to run as soon as possible.
    ///
    /// This method returns immediately, and errors only if we are unable to send the request.
    /// The reducer will run asynchronously in the future,
    ///  and its status can be observed by listening for [`Self::on_insert_into_indexed_simple_enum`] callbacks.
    fn insert_into_indexed_simple_enum(&self, n: SimpleEnum) -> __sdk::Result<()>;
    /// Register a callback to run whenever we are notified of an invocation of the reducer `insert_into_indexed_simple_enum`.
    ///
    /// Callbacks should inspect the [`__sdk::ReducerEvent`] contained in the [`super::ReducerEventContext`]
    /// to determine the reducer's status.
    ///
    /// The returned [`InsertIntoIndexedSimpleEnumCallbackId`] can be passed to [`Self::remove_on_insert_into_indexed_simple_enum`]
    /// to cancel the callback.
    fn on_insert_into_indexed_simple_enum(
        &self,
        callback: impl FnMut(&super::ReducerEventContext, &SimpleEnum) + Send + 'static,
    ) -> InsertIntoIndexedSimpleEnumCallbackId;
    /// Cancel a callback previously registered by [`Self::on_insert_into_indexed_simple_enum`],
    /// causing it not to run in the future.
    fn remove_on_insert_into_indexed_simple_enum(&self, callback: InsertIntoIndexedSimpleEnumCallbackId);
}

impl insert_into_indexed_simple_enum for super::RemoteReducers {
    fn insert_into_indexed_simple_enum(&self, n: SimpleEnum) -> __sdk::Result<()> {
        self.imp
            .call_reducer("insert_into_indexed_simple_enum", InsertIntoIndexedSimpleEnumArgs { n })
    }
    fn on_insert_into_indexed_simple_enum(
        &self,
        mut callback: impl FnMut(&super::ReducerEventContext, &SimpleEnum) + Send + 'static,
    ) -> InsertIntoIndexedSimpleEnumCallbackId {
        InsertIntoIndexedSimpleEnumCallbackId(self.imp.on_reducer(
            "insert_into_indexed_simple_enum",
            Box::new(move |ctx: &super::ReducerEventContext| {
                let super::ReducerEventContext {
                    event:
                        __sdk::ReducerEvent {
                            reducer: super::Reducer::InsertIntoIndexedSimpleEnum { n },
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
    fn remove_on_insert_into_indexed_simple_enum(&self, callback: InsertIntoIndexedSimpleEnumCallbackId) {
        self.imp
            .remove_on_reducer("insert_into_indexed_simple_enum", callback.0)
    }
}

#[allow(non_camel_case_types)]
#[doc(hidden)]
/// Extension trait for setting the call-flags for the reducer `insert_into_indexed_simple_enum`.
///
/// Implemented for [`super::SetReducerFlags`].
///
/// This type is currently unstable and may be removed without a major version bump.
pub trait set_flags_for_insert_into_indexed_simple_enum {
    /// Set the call-reducer flags for the reducer `insert_into_indexed_simple_enum` to `flags`.
    ///
    /// This type is currently unstable and may be removed without a major version bump.
    fn insert_into_indexed_simple_enum(&self, flags: __ws::CallReducerFlags);
}

impl set_flags_for_insert_into_indexed_simple_enum for super::SetReducerFlags {
    fn insert_into_indexed_simple_enum(&self, flags: __ws::CallReducerFlags) {
        self.imp
            .set_call_reducer_flags("insert_into_indexed_simple_enum", flags);
    }
}
