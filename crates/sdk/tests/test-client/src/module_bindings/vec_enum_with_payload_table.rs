// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN YOUR MODULE SOURCE CODE INSTEAD.

#![allow(unused, clippy::all)]
use super::enum_with_payload_type::EnumWithPayload;
use super::vec_enum_with_payload_type::VecEnumWithPayload;
use spacetimedb_sdk::__codegen::{self as __sdk, __lib, __sats, __ws};

/// Table handle for the table `vec_enum_with_payload`.
///
/// Obtain a handle from the [`VecEnumWithPayloadTableAccess::vec_enum_with_payload`] method on [`super::RemoteTables`],
/// like `ctx.db.vec_enum_with_payload()`.
///
/// Users are encouraged not to explicitly reference this type,
/// but to directly chain method calls,
/// like `ctx.db.vec_enum_with_payload().on_insert(...)`.
pub struct VecEnumWithPayloadTableHandle<'ctx> {
    imp: __sdk::TableHandle<VecEnumWithPayload>,
    ctx: std::marker::PhantomData<&'ctx super::RemoteTables>,
}

#[allow(non_camel_case_types)]
/// Extension trait for access to the table `vec_enum_with_payload`.
///
/// Implemented for [`super::RemoteTables`].
pub trait VecEnumWithPayloadTableAccess {
    #[allow(non_snake_case)]
    /// Obtain a [`VecEnumWithPayloadTableHandle`], which mediates access to the table `vec_enum_with_payload`.
    fn vec_enum_with_payload(&self) -> VecEnumWithPayloadTableHandle<'_>;
}

impl VecEnumWithPayloadTableAccess for super::RemoteTables {
    fn vec_enum_with_payload(&self) -> VecEnumWithPayloadTableHandle<'_> {
        VecEnumWithPayloadTableHandle {
            imp: self.imp.get_table::<VecEnumWithPayload>("vec_enum_with_payload"),
            ctx: std::marker::PhantomData,
        }
    }
}

pub struct VecEnumWithPayloadInsertCallbackId(__sdk::CallbackId);
pub struct VecEnumWithPayloadDeleteCallbackId(__sdk::CallbackId);

impl<'ctx> __sdk::Table for VecEnumWithPayloadTableHandle<'ctx> {
    type Row = VecEnumWithPayload;
    type EventContext = super::EventContext;

    fn count(&self) -> u64 {
        self.imp.count()
    }
    fn iter(&self) -> impl Iterator<Item = VecEnumWithPayload> + '_ {
        self.imp.iter()
    }

    type InsertCallbackId = VecEnumWithPayloadInsertCallbackId;

    fn on_insert(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row) + Send + 'static,
    ) -> VecEnumWithPayloadInsertCallbackId {
        VecEnumWithPayloadInsertCallbackId(self.imp.on_insert(Box::new(callback)))
    }

    fn remove_on_insert(&self, callback: VecEnumWithPayloadInsertCallbackId) {
        self.imp.remove_on_insert(callback.0)
    }

    type DeleteCallbackId = VecEnumWithPayloadDeleteCallbackId;

    fn on_delete(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row) + Send + 'static,
    ) -> VecEnumWithPayloadDeleteCallbackId {
        VecEnumWithPayloadDeleteCallbackId(self.imp.on_delete(Box::new(callback)))
    }

    fn remove_on_delete(&self, callback: VecEnumWithPayloadDeleteCallbackId) {
        self.imp.remove_on_delete(callback.0)
    }
}

#[doc(hidden)]
pub(super) fn register_table(client_cache: &mut __sdk::ClientCache<super::RemoteModule>) {
    let _table = client_cache.get_or_make_table::<VecEnumWithPayload>("vec_enum_with_payload");
}

#[doc(hidden)]
pub(super) fn parse_table_update(
    raw_updates: __ws::TableUpdate<__ws::BsatnFormat>,
) -> __sdk::Result<__sdk::TableUpdate<VecEnumWithPayload>> {
    __sdk::TableUpdate::parse_table_update(raw_updates).map_err(|e| {
        __sdk::InternalError::failed_parse("TableUpdate<VecEnumWithPayload>", "TableUpdate")
            .with_cause(e)
            .into()
    })
}
