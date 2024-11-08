// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN RUST INSTEAD.

#![allow(unused)]
use super::pk_u_8_type::PkU8;
use spacetimedb_sdk::{
    self as __sdk,
    anyhow::{self as __anyhow, Context as _},
    lib as __lib, sats as __sats, ws_messages as __ws,
};

/// Table handle for the table `pk_u8`.
///
/// Obtain a handle from the [`PkU8TableAccess::pk_u_8`] method on [`super::RemoteTables`],
/// like `ctx.db.pk_u_8()`.
///
/// Users are encouraged not to explicitly reference this type,
/// but to directly chain method calls,
/// like `ctx.db.pk_u_8().on_insert(...)`.
pub struct PkU8TableHandle<'ctx> {
    imp: __sdk::db_connection::TableHandle<PkU8>,
    ctx: std::marker::PhantomData<&'ctx super::RemoteTables>,
}

#[allow(non_camel_case_types)]
/// Extension trait for access to the table `pk_u8`.
///
/// Implemented for [`super::RemoteTables`].
pub trait PkU8TableAccess {
    #[allow(non_snake_case)]
    /// Obtain a [`PkU8TableHandle`], which mediates access to the table `pk_u8`.
    fn pk_u_8(&self) -> PkU8TableHandle<'_>;
}

impl PkU8TableAccess for super::RemoteTables {
    fn pk_u_8(&self) -> PkU8TableHandle<'_> {
        PkU8TableHandle {
            imp: self.imp.get_table::<PkU8>("pk_u8"),
            ctx: std::marker::PhantomData,
        }
    }
}

pub struct PkU8InsertCallbackId(__sdk::callbacks::CallbackId);
pub struct PkU8DeleteCallbackId(__sdk::callbacks::CallbackId);

impl<'ctx> __sdk::table::Table for PkU8TableHandle<'ctx> {
    type Row = PkU8;
    type EventContext = super::EventContext;

    fn count(&self) -> u64 {
        self.imp.count()
    }
    fn iter(&self) -> impl Iterator<Item = PkU8> + '_ {
        self.imp.iter()
    }

    type InsertCallbackId = PkU8InsertCallbackId;

    fn on_insert(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row) + Send + 'static,
    ) -> PkU8InsertCallbackId {
        PkU8InsertCallbackId(self.imp.on_insert(Box::new(callback)))
    }

    fn remove_on_insert(&self, callback: PkU8InsertCallbackId) {
        self.imp.remove_on_insert(callback.0)
    }

    type DeleteCallbackId = PkU8DeleteCallbackId;

    fn on_delete(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row) + Send + 'static,
    ) -> PkU8DeleteCallbackId {
        PkU8DeleteCallbackId(self.imp.on_delete(Box::new(callback)))
    }

    fn remove_on_delete(&self, callback: PkU8DeleteCallbackId) {
        self.imp.remove_on_delete(callback.0)
    }
}

pub struct PkU8UpdateCallbackId(__sdk::callbacks::CallbackId);

impl<'ctx> __sdk::table::TableWithPrimaryKey for PkU8TableHandle<'ctx> {
    type UpdateCallbackId = PkU8UpdateCallbackId;

    fn on_update(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row, &Self::Row) + Send + 'static,
    ) -> PkU8UpdateCallbackId {
        PkU8UpdateCallbackId(self.imp.on_update(Box::new(callback)))
    }

    fn remove_on_update(&self, callback: PkU8UpdateCallbackId) {
        self.imp.remove_on_update(callback.0)
    }
}

#[doc(hidden)]
pub(super) fn parse_table_update(
    raw_updates: __ws::TableUpdate<__ws::BsatnFormat>,
) -> __anyhow::Result<__sdk::spacetime_module::TableUpdate<PkU8>> {
    __sdk::spacetime_module::TableUpdate::parse_table_update_with_primary_key::<u8>(raw_updates, |row: &PkU8| &row.n)
        .context("Failed to parse table update for table \"pk_u8\"")
}

/// Access to the `n` unique index on the table `pk_u8`,
/// which allows point queries on the field of the same name
/// via the [`PkU8NUnique::find`] method.
///
/// Users are encouraged not to explicitly reference this type,
/// but to directly chain method calls,
/// like `ctx.db.pk_u_8().n().find(...)`.
pub struct PkU8NUnique<'ctx> {
    imp: __sdk::client_cache::UniqueConstraint<PkU8, u8>,
    phantom: std::marker::PhantomData<&'ctx super::RemoteTables>,
}

impl<'ctx> PkU8TableHandle<'ctx> {
    /// Get a handle on the `n` unique index on the table `pk_u8`.
    pub fn n(&self) -> PkU8NUnique<'ctx> {
        PkU8NUnique {
            imp: self.imp.get_unique_constraint::<u8>("n", |row| &row.n),
            phantom: std::marker::PhantomData,
        }
    }
}

impl<'ctx> PkU8NUnique<'ctx> {
    /// Find the subscribed row whose `n` column value is equal to `col_val`,
    /// if such a row is present in the client cache.
    pub fn find(&self, col_val: &u8) -> Option<PkU8> {
        self.imp.find(col_val)
    }
}
