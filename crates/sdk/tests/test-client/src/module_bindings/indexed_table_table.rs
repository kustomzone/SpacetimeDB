// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN YOUR MODULE SOURCE CODE INSTEAD.

#![allow(unused, clippy::all)]
use super::indexed_table_type::IndexedTable;
use spacetimedb_sdk::__codegen::{self as __sdk, __lib, __sats, __ws};

/// Table handle for the table `indexed_table`.
///
/// Obtain a handle from the [`IndexedTableTableAccess::indexed_table`] method on [`super::RemoteTables`],
/// like `ctx.db.indexed_table()`.
///
/// Users are encouraged not to explicitly reference this type,
/// but to directly chain method calls,
/// like `ctx.db.indexed_table().on_insert(...)`.
pub struct IndexedTableTableHandle<'ctx> {
    imp: __sdk::TableHandle<IndexedTable>,
    ctx: std::marker::PhantomData<&'ctx super::RemoteTables>,
}

#[allow(non_camel_case_types)]
/// Extension trait for access to the table `indexed_table`.
///
/// Implemented for [`super::RemoteTables`].
pub trait IndexedTableTableAccess {
    #[allow(non_snake_case)]
    /// Obtain a [`IndexedTableTableHandle`], which mediates access to the table `indexed_table`.
    fn indexed_table(&self) -> IndexedTableTableHandle<'_>;
}

impl IndexedTableTableAccess for super::RemoteTables {
    fn indexed_table(&self) -> IndexedTableTableHandle<'_> {
        IndexedTableTableHandle {
            imp: self.imp.get_table::<IndexedTable>("indexed_table"),
            ctx: std::marker::PhantomData,
        }
    }
}

pub struct IndexedTableInsertCallbackId(__sdk::CallbackId);
pub struct IndexedTableDeleteCallbackId(__sdk::CallbackId);

impl<'ctx> __sdk::Table for IndexedTableTableHandle<'ctx> {
    type Row = IndexedTable;
    type EventContext = super::EventContext;

    fn count(&self) -> u64 {
        self.imp.count()
    }
    fn iter(&self) -> impl Iterator<Item = IndexedTable> + '_ {
        self.imp.iter()
    }

    type InsertCallbackId = IndexedTableInsertCallbackId;

    fn on_insert(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row) + Send + 'static,
    ) -> IndexedTableInsertCallbackId {
        IndexedTableInsertCallbackId(self.imp.on_insert(Box::new(callback)))
    }

    fn remove_on_insert(&self, callback: IndexedTableInsertCallbackId) {
        self.imp.remove_on_insert(callback.0)
    }

    type DeleteCallbackId = IndexedTableDeleteCallbackId;

    fn on_delete(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row) + Send + 'static,
    ) -> IndexedTableDeleteCallbackId {
        IndexedTableDeleteCallbackId(self.imp.on_delete(Box::new(callback)))
    }

    fn remove_on_delete(&self, callback: IndexedTableDeleteCallbackId) {
        self.imp.remove_on_delete(callback.0)
    }
}

#[doc(hidden)]
pub(super) fn register_table(client_cache: &mut __sdk::ClientCache<super::RemoteModule>) {
    let _table = client_cache.get_or_make_table::<IndexedTable>("indexed_table");
}
#[doc(hidden)]
pub(super) fn parse_table_update(
    raw_updates: __ws::TableUpdate<__ws::BsatnFormat>,
) -> __sdk::Result<__sdk::TableUpdate<IndexedTable>> {
    __sdk::TableUpdate::parse_table_update_no_primary_key(raw_updates).map_err(|e| {
        __sdk::InternalError::failed_parse("TableUpdate<IndexedTable>", "TableUpdate")
            .with_cause(e)
            .into()
    })
}
