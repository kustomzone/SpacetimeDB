// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN YOUR MODULE SOURCE CODE INSTEAD.

#![allow(unused, clippy::all)]
use super::one_u_32_type::OneU32;
use spacetimedb_sdk::__codegen::{self as __sdk, __lib, __sats, __ws};

/// Table handle for the table `one_u32`.
///
/// Obtain a handle from the [`OneU32TableAccess::one_u_32`] method on [`super::RemoteTables`],
/// like `ctx.db.one_u_32()`.
///
/// Users are encouraged not to explicitly reference this type,
/// but to directly chain method calls,
/// like `ctx.db.one_u_32().on_insert(...)`.
pub struct OneU32TableHandle<'ctx> {
    imp: __sdk::TableHandle<OneU32>,
    ctx: std::marker::PhantomData<&'ctx super::RemoteTables>,
}

#[allow(non_camel_case_types)]
/// Extension trait for access to the table `one_u32`.
///
/// Implemented for [`super::RemoteTables`].
pub trait OneU32TableAccess {
    #[allow(non_snake_case)]
    /// Obtain a [`OneU32TableHandle`], which mediates access to the table `one_u32`.
    fn one_u_32(&self) -> OneU32TableHandle<'_>;
}

impl OneU32TableAccess for super::RemoteTables {
    fn one_u_32(&self) -> OneU32TableHandle<'_> {
        OneU32TableHandle {
            imp: self.imp.get_table::<OneU32>("one_u32"),
            ctx: std::marker::PhantomData,
        }
    }
}

pub struct OneU32InsertCallbackId(__sdk::CallbackId);
pub struct OneU32DeleteCallbackId(__sdk::CallbackId);

impl<'ctx> __sdk::Table for OneU32TableHandle<'ctx> {
    type Row = OneU32;
    type EventContext = super::EventContext;

    fn count(&self) -> u64 {
        self.imp.count()
    }
    fn iter(&self) -> impl Iterator<Item = OneU32> + '_ {
        self.imp.iter()
    }

    type InsertCallbackId = OneU32InsertCallbackId;

    fn on_insert(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row) + Send + 'static,
    ) -> OneU32InsertCallbackId {
        OneU32InsertCallbackId(self.imp.on_insert(Box::new(callback)))
    }

    fn remove_on_insert(&self, callback: OneU32InsertCallbackId) {
        self.imp.remove_on_insert(callback.0)
    }

    type DeleteCallbackId = OneU32DeleteCallbackId;

    fn on_delete(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row) + Send + 'static,
    ) -> OneU32DeleteCallbackId {
        OneU32DeleteCallbackId(self.imp.on_delete(Box::new(callback)))
    }

    fn remove_on_delete(&self, callback: OneU32DeleteCallbackId) {
        self.imp.remove_on_delete(callback.0)
    }
}

#[doc(hidden)]
pub(super) fn register_table(client_cache: &mut __sdk::ClientCache<super::RemoteModule>) {
    let _table = client_cache.get_or_make_table::<OneU32>("one_u32");
}

#[doc(hidden)]
pub(super) fn parse_table_update(
    raw_updates: __ws::TableUpdate<__ws::BsatnFormat>,
) -> __sdk::Result<__sdk::TableUpdate<OneU32>> {
    __sdk::TableUpdate::parse_table_update(raw_updates).map_err(|e| {
        __sdk::InternalError::failed_parse("TableUpdate<OneU32>", "TableUpdate")
            .with_cause(e)
            .into()
    })
}
