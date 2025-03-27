// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN YOUR MODULE SOURCE CODE INSTEAD.

#![allow(unused, clippy::all)]
use super::indexed_table_2_type::IndexedTable2;
use spacetimedb_sdk::__codegen::{self as __sdk, __lib, __sats, __ws};

/// Table handle for the table `indexed_table_2`.
///
/// Obtain a handle from the [`IndexedTable2TableAccess::indexed_table_2`] method on [`super::RemoteTables`],
/// like `ctx.db.indexed_table_2()`.
///
/// Users are encouraged not to explicitly reference this type,
/// but to directly chain method calls,
/// like `ctx.db.indexed_table_2().on_insert(...)`.
pub struct IndexedTable2TableHandle<'ctx> {
    imp: __sdk::TableHandle<IndexedTable2>,
    ctx: std::marker::PhantomData<&'ctx super::RemoteTables>,
}

#[allow(non_camel_case_types)]
/// Extension trait for access to the table `indexed_table_2`.
///
/// Implemented for [`super::RemoteTables`].
pub trait IndexedTable2TableAccess {
    #[allow(non_snake_case)]
    /// Obtain a [`IndexedTable2TableHandle`], which mediates access to the table `indexed_table_2`.
    fn indexed_table_2(&self) -> IndexedTable2TableHandle<'_>;
}

impl IndexedTable2TableAccess for super::RemoteTables {
    fn indexed_table_2(&self) -> IndexedTable2TableHandle<'_> {
        IndexedTable2TableHandle {
            imp: self.imp.get_table::<IndexedTable2>("indexed_table_2"),
            ctx: std::marker::PhantomData,
        }
    }
}

pub struct IndexedTable2InsertCallbackId(__sdk::CallbackId);
pub struct IndexedTable2DeleteCallbackId(__sdk::CallbackId);

impl<'ctx> __sdk::Table for IndexedTable2TableHandle<'ctx> {
    type Row = IndexedTable2;
    type EventContext = super::EventContext;

    fn count(&self) -> u64 {
        self.imp.count()
    }
    fn iter(&self) -> impl Iterator<Item = IndexedTable2> + '_ {
        self.imp.iter()
    }

    type InsertCallbackId = IndexedTable2InsertCallbackId;

    fn on_insert(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row) + Send + 'static,
    ) -> IndexedTable2InsertCallbackId {
        IndexedTable2InsertCallbackId(self.imp.on_insert(Box::new(callback)))
    }

    fn remove_on_insert(&self, callback: IndexedTable2InsertCallbackId) {
        self.imp.remove_on_insert(callback.0)
    }

    type DeleteCallbackId = IndexedTable2DeleteCallbackId;

    fn on_delete(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row) + Send + 'static,
    ) -> IndexedTable2DeleteCallbackId {
        IndexedTable2DeleteCallbackId(self.imp.on_delete(Box::new(callback)))
    }

    fn remove_on_delete(&self, callback: IndexedTable2DeleteCallbackId) {
        self.imp.remove_on_delete(callback.0)
    }
}

#[doc(hidden)]
pub(super) fn register_table(client_cache: &mut __sdk::ClientCache<super::RemoteModule>) {
    let _table = client_cache.get_or_make_table::<IndexedTable2>("indexed_table_2");
}

#[doc(hidden)]
pub(super) fn parse_table_update(
    raw_updates: __ws::TableUpdate<__ws::BsatnFormat>,
) -> __sdk::Result<__sdk::TableUpdate<IndexedTable2>> {
    __sdk::TableUpdate::parse_table_update(raw_updates).map_err(|e| {
        __sdk::InternalError::failed_parse("TableUpdate<IndexedTable2>", "TableUpdate")
            .with_cause(e)
            .into()
    })
}
