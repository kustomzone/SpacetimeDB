// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN RUST INSTEAD.

#![allow(unused, clippy::all)]
use spacetimedb_sdk::__codegen::{self as __sdk, __lib, __sats, __ws};

#[derive(__lib::ser::Serialize, __lib::de::Deserialize, Clone, PartialEq, Debug)]
#[sats(crate = __lib)]
pub(super) struct UpdateUniqueU16Args {
    pub n: u16,
    pub data: i32,
}

impl From<UpdateUniqueU16Args> for super::Reducer {
    fn from(args: UpdateUniqueU16Args) -> Self {
        Self::UpdateUniqueU16 {
            n: args.n,
            data: args.data,
        }
    }
}

impl __sdk::InModule for UpdateUniqueU16Args {
    type Module = super::RemoteModule;
}

pub struct UpdateUniqueU16CallbackId(__sdk::CallbackId);

#[allow(non_camel_case_types)]
/// Extension trait for access to the reducer `update_unique_u16`.
///
/// Implemented for [`super::RemoteReducers`].
pub trait update_unique_u_16 {
    /// Request that the remote module invoke the reducer `update_unique_u16` to run as soon as possible.
    ///
    /// This method returns immediately, and errors only if we are unable to send the request.
    /// The reducer will run asynchronously in the future,
    ///  and its status can be observed by listening for [`Self::on_update_unique_u_16`] callbacks.
    fn update_unique_u_16(&self, n: u16, data: i32) -> __sdk::Result<()>;
    /// Register a callback to run whenever we are notified of an invocation of the reducer `update_unique_u16`.
    ///
    /// Callbacks should inspect the [`__sdk::ReducerEvent`] contained in the [`super::ReducerEventContext`]
    /// to determine the reducer's status.
    ///
    /// The returned [`UpdateUniqueU16CallbackId`] can be passed to [`Self::remove_on_update_unique_u_16`]
    /// to cancel the callback.
    fn on_update_unique_u_16(
        &self,
        callback: impl FnMut(&super::ReducerEventContext, &u16, &i32) + Send + 'static,
    ) -> UpdateUniqueU16CallbackId;
    /// Cancel a callback previously registered by [`Self::on_update_unique_u_16`],
    /// causing it not to run in the future.
    fn remove_on_update_unique_u_16(&self, callback: UpdateUniqueU16CallbackId);
}

impl update_unique_u_16 for super::RemoteReducers {
    fn update_unique_u_16(&self, n: u16, data: i32) -> __sdk::Result<()> {
        self.imp
            .call_reducer("update_unique_u16", UpdateUniqueU16Args { n, data })
    }
    fn on_update_unique_u_16(
        &self,
        mut callback: impl FnMut(&super::ReducerEventContext, &u16, &i32) + Send + 'static,
    ) -> UpdateUniqueU16CallbackId {
        UpdateUniqueU16CallbackId(self.imp.on_reducer(
            "update_unique_u16",
            Box::new(move |ctx: &super::ReducerEventContext| {
                let super::ReducerEventContext {
                    event:
                        __sdk::ReducerEvent {
                            reducer: super::Reducer::UpdateUniqueU16 { n, data },
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
    fn remove_on_update_unique_u_16(&self, callback: UpdateUniqueU16CallbackId) {
        self.imp.remove_on_reducer("update_unique_u16", callback.0)
    }
}

#[allow(non_camel_case_types)]
#[doc(hidden)]
/// Extension trait for setting the call-flags for the reducer `update_unique_u16`.
///
/// Implemented for [`super::SetReducerFlags`].
///
/// This type is currently unstable and may be removed without a major version bump.
pub trait set_flags_for_update_unique_u_16 {
    /// Set the call-reducer flags for the reducer `update_unique_u16` to `flags`.
    ///
    /// This type is currently unstable and may be removed without a major version bump.
    fn update_unique_u_16(&self, flags: __ws::CallReducerFlags);
}

impl set_flags_for_update_unique_u_16 for super::SetReducerFlags {
    fn update_unique_u_16(&self, flags: __ws::CallReducerFlags) {
        self.imp.set_call_reducer_flags("update_unique_u16", flags);
    }
}
