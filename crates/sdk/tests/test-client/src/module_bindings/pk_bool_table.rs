// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN RUST INSTEAD.

#![allow(unused)]
use super::pk_bool_type::PkBool;
use spacetimedb_sdk::__codegen::{
    self as __sdk, __lib, __sats, __ws,
    anyhow::{self as __anyhow, Context as _},
};

/// Table handle for the table `pk_bool`.
///
/// Obtain a handle from the [`PkBoolTableAccess::pk_bool`] method on [`super::RemoteTables`],
/// like `ctx.db.pk_bool()`.
///
/// Users are encouraged not to explicitly reference this type,
/// but to directly chain method calls,
/// like `ctx.db.pk_bool().on_insert(...)`.
pub struct PkBoolTableHandle<'ctx> {
    imp: __sdk::TableHandle<PkBool>,
    ctx: std::marker::PhantomData<&'ctx super::RemoteTables>,
}

#[allow(non_camel_case_types)]
/// Extension trait for access to the table `pk_bool`.
///
/// Implemented for [`super::RemoteTables`].
pub trait PkBoolTableAccess {
    #[allow(non_snake_case)]
    /// Obtain a [`PkBoolTableHandle`], which mediates access to the table `pk_bool`.
    fn pk_bool(&self) -> PkBoolTableHandle<'_>;
}

impl PkBoolTableAccess for super::RemoteTables {
    fn pk_bool(&self) -> PkBoolTableHandle<'_> {
        PkBoolTableHandle {
            imp: self.imp.get_table::<PkBool>("pk_bool"),
            ctx: std::marker::PhantomData,
        }
    }
}

pub struct PkBoolInsertCallbackId(__sdk::CallbackId);
pub struct PkBoolDeleteCallbackId(__sdk::CallbackId);

impl<'ctx> __sdk::Table for PkBoolTableHandle<'ctx> {
    type Row = PkBool;
    type EventContext = super::EventContext;

    fn count(&self) -> u64 {
        self.imp.count()
    }
    fn iter(&self) -> impl Iterator<Item = PkBool> + '_ {
        self.imp.iter()
    }

    type InsertCallbackId = PkBoolInsertCallbackId;

    fn on_insert(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row) + Send + 'static,
    ) -> PkBoolInsertCallbackId {
        PkBoolInsertCallbackId(self.imp.on_insert(Box::new(callback)))
    }

    fn remove_on_insert(&self, callback: PkBoolInsertCallbackId) {
        self.imp.remove_on_insert(callback.0)
    }

    type DeleteCallbackId = PkBoolDeleteCallbackId;

    fn on_delete(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row) + Send + 'static,
    ) -> PkBoolDeleteCallbackId {
        PkBoolDeleteCallbackId(self.imp.on_delete(Box::new(callback)))
    }

    fn remove_on_delete(&self, callback: PkBoolDeleteCallbackId) {
        self.imp.remove_on_delete(callback.0)
    }
}

#[doc(hidden)]
pub(super) fn register_table(client_cache: &mut __sdk::ClientCache<super::RemoteModule>) {
    let _table = client_cache.get_or_make_table::<PkBool>("pk_bool");
    _table.add_unique_constraint::<bool>("b", |row| &row.b)
}
pub struct PkBoolUpdateCallbackId(__sdk::CallbackId);

impl<'ctx> __sdk::TableWithPrimaryKey for PkBoolTableHandle<'ctx> {
    type UpdateCallbackId = PkBoolUpdateCallbackId;

    fn on_update(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row, &Self::Row) + Send + 'static,
    ) -> PkBoolUpdateCallbackId {
        PkBoolUpdateCallbackId(self.imp.on_update(Box::new(callback)))
    }

    fn remove_on_update(&self, callback: PkBoolUpdateCallbackId) {
        self.imp.remove_on_update(callback.0)
    }
}

#[doc(hidden)]
pub(super) fn parse_table_update(
    raw_updates: __ws::TableUpdate<__ws::BsatnFormat>,
) -> __anyhow::Result<__sdk::TableUpdate<PkBool>> {
    __sdk::TableUpdate::parse_table_update_with_primary_key::<bool>(raw_updates, |row: &PkBool| &row.b)
        .context("Failed to parse table update for table \"pk_bool\"")
}

/// Access to the `b` unique index on the table `pk_bool`,
/// which allows point queries on the field of the same name
/// via the [`PkBoolBUnique::find`] method.
///
/// Users are encouraged not to explicitly reference this type,
/// but to directly chain method calls,
/// like `ctx.db.pk_bool().b().find(...)`.
pub struct PkBoolBUnique<'ctx> {
    imp: __sdk::UniqueConstraintHandle<PkBool, bool>,
    phantom: std::marker::PhantomData<&'ctx super::RemoteTables>,
}

impl<'ctx> PkBoolTableHandle<'ctx> {
    /// Get a handle on the `b` unique index on the table `pk_bool`.
    pub fn b(&self) -> PkBoolBUnique<'ctx> {
        PkBoolBUnique {
            imp: self.imp.get_unique_constraint::<bool>("b"),
            phantom: std::marker::PhantomData,
        }
    }
}

impl<'ctx> PkBoolBUnique<'ctx> {
    /// Find the subscribed row whose `b` column value is equal to `col_val`,
    /// if such a row is present in the client cache.
    pub fn find(&self, col_val: &bool) -> Option<PkBool> {
        self.imp.find(col_val)
    }
}
