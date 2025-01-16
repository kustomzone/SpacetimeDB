// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN RUST INSTEAD.

#![allow(unused)]
use super::scheduled_table_type::ScheduledTable;
use spacetimedb_sdk::__codegen::{
    self as __sdk, __lib, __sats, __ws,
    anyhow::{self as __anyhow, Context as _},
};

/// Table handle for the table `scheduled_table`.
///
/// Obtain a handle from the [`ScheduledTableTableAccess::scheduled_table`] method on [`super::RemoteTables`],
/// like `ctx.db.scheduled_table()`.
///
/// Users are encouraged not to explicitly reference this type,
/// but to directly chain method calls,
/// like `ctx.db.scheduled_table().on_insert(...)`.
pub struct ScheduledTableTableHandle<'ctx> {
    imp: __sdk::TableHandle<ScheduledTable>,
    ctx: std::marker::PhantomData<&'ctx super::RemoteTables>,
}

#[allow(non_camel_case_types)]
/// Extension trait for access to the table `scheduled_table`.
///
/// Implemented for [`super::RemoteTables`].
pub trait ScheduledTableTableAccess {
    #[allow(non_snake_case)]
    /// Obtain a [`ScheduledTableTableHandle`], which mediates access to the table `scheduled_table`.
    fn scheduled_table(&self) -> ScheduledTableTableHandle<'_>;
}

impl ScheduledTableTableAccess for super::RemoteTables {
    fn scheduled_table(&self) -> ScheduledTableTableHandle<'_> {
        ScheduledTableTableHandle {
            imp: self.imp.get_table::<ScheduledTable>("scheduled_table"),
            ctx: std::marker::PhantomData,
        }
    }
}

pub struct ScheduledTableInsertCallbackId(__sdk::CallbackId);
pub struct ScheduledTableDeleteCallbackId(__sdk::CallbackId);

impl<'ctx> __sdk::Table for ScheduledTableTableHandle<'ctx> {
    type Row = ScheduledTable;
    type EventContext = super::EventContext;

    fn count(&self) -> u64 {
        self.imp.count()
    }
    fn iter(&self) -> impl Iterator<Item = ScheduledTable> + '_ {
        self.imp.iter()
    }

    type InsertCallbackId = ScheduledTableInsertCallbackId;

    fn on_insert(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row) + Send + 'static,
    ) -> ScheduledTableInsertCallbackId {
        ScheduledTableInsertCallbackId(self.imp.on_insert(Box::new(callback)))
    }

    fn remove_on_insert(&self, callback: ScheduledTableInsertCallbackId) {
        self.imp.remove_on_insert(callback.0)
    }

    type DeleteCallbackId = ScheduledTableDeleteCallbackId;

    fn on_delete(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row) + Send + 'static,
    ) -> ScheduledTableDeleteCallbackId {
        ScheduledTableDeleteCallbackId(self.imp.on_delete(Box::new(callback)))
    }

    fn remove_on_delete(&self, callback: ScheduledTableDeleteCallbackId) {
        self.imp.remove_on_delete(callback.0)
    }
}

#[doc(hidden)]
pub(super) fn register_table(client_cache: &mut __sdk::ClientCache<super::RemoteModule>) {
    let _table = client_cache.get_or_make_table::<ScheduledTable>("scheduled_table");
    _table.add_unique_constraint::<u64>("scheduled_id", |row| &row.scheduled_id);
}
pub struct ScheduledTableUpdateCallbackId(__sdk::CallbackId);

impl<'ctx> __sdk::TableWithPrimaryKey for ScheduledTableTableHandle<'ctx> {
    type UpdateCallbackId = ScheduledTableUpdateCallbackId;

    fn on_update(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row, &Self::Row) + Send + 'static,
    ) -> ScheduledTableUpdateCallbackId {
        ScheduledTableUpdateCallbackId(self.imp.on_update(Box::new(callback)))
    }

    fn remove_on_update(&self, callback: ScheduledTableUpdateCallbackId) {
        self.imp.remove_on_update(callback.0)
    }
}

#[doc(hidden)]
pub(super) fn parse_table_update(
    raw_updates: __ws::TableUpdate<__ws::BsatnFormat>,
) -> __anyhow::Result<__sdk::TableUpdate<ScheduledTable>> {
    __sdk::TableUpdate::parse_table_update_with_primary_key::<u64>(raw_updates, |row: &ScheduledTable| {
        &row.scheduled_id
    })
    .context("Failed to parse table update for table \"scheduled_table\"")
}

/// Access to the `scheduled_id` unique index on the table `scheduled_table`,
/// which allows point queries on the field of the same name
/// via the [`ScheduledTableScheduledIdUnique::find`] method.
///
/// Users are encouraged not to explicitly reference this type,
/// but to directly chain method calls,
/// like `ctx.db.scheduled_table().scheduled_id().find(...)`.
pub struct ScheduledTableScheduledIdUnique<'ctx> {
    imp: __sdk::UniqueConstraintHandle<ScheduledTable, u64>,
    phantom: std::marker::PhantomData<&'ctx super::RemoteTables>,
}

impl<'ctx> ScheduledTableTableHandle<'ctx> {
    /// Get a handle on the `scheduled_id` unique index on the table `scheduled_table`.
    pub fn scheduled_id(&self) -> ScheduledTableScheduledIdUnique<'ctx> {
        ScheduledTableScheduledIdUnique {
            imp: self.imp.get_unique_constraint::<u64>("scheduled_id"),
            phantom: std::marker::PhantomData,
        }
    }
}

impl<'ctx> ScheduledTableScheduledIdUnique<'ctx> {
    /// Find the subscribed row whose `scheduled_id` column value is equal to `col_val`,
    /// if such a row is present in the client cache.
    pub fn find(&self, col_val: &u64) -> Option<ScheduledTable> {
        self.imp.find(col_val)
    }
}
