// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN YOUR MODULE SOURCE CODE INSTEAD.

#![allow(unused, clippy::all)]
use super::pk_u_32_type::PkU32;
use spacetimedb_sdk::__codegen::{self as __sdk, __lib, __sats, __ws};

/// Table handle for the table `pk_u32`.
///
/// Obtain a handle from the [`PkU32TableAccess::pk_u_32`] method on [`super::RemoteTables`],
/// like `ctx.db.pk_u_32()`.
///
/// Users are encouraged not to explicitly reference this type,
/// but to directly chain method calls,
/// like `ctx.db.pk_u_32().on_insert(...)`.
pub struct PkU32TableHandle<'ctx> {
    imp: __sdk::TableHandle<PkU32>,
    ctx: std::marker::PhantomData<&'ctx super::RemoteTables>,
}

#[allow(non_camel_case_types)]
/// Extension trait for access to the table `pk_u32`.
///
/// Implemented for [`super::RemoteTables`].
pub trait PkU32TableAccess {
    #[allow(non_snake_case)]
    /// Obtain a [`PkU32TableHandle`], which mediates access to the table `pk_u32`.
    fn pk_u_32(&self) -> PkU32TableHandle<'_>;
}

impl PkU32TableAccess for super::RemoteTables {
    fn pk_u_32(&self) -> PkU32TableHandle<'_> {
        PkU32TableHandle {
            imp: self.imp.get_table::<PkU32>("pk_u32"),
            ctx: std::marker::PhantomData,
        }
    }
}

pub struct PkU32InsertCallbackId(__sdk::CallbackId);
pub struct PkU32DeleteCallbackId(__sdk::CallbackId);

impl<'ctx> __sdk::Table for PkU32TableHandle<'ctx> {
    type Row = PkU32;
    type EventContext = super::EventContext;

    fn count(&self) -> u64 {
        self.imp.count()
    }
    fn iter(&self) -> impl Iterator<Item = PkU32> + '_ {
        self.imp.iter()
    }

    type InsertCallbackId = PkU32InsertCallbackId;

    fn on_insert(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row) + Send + 'static,
    ) -> PkU32InsertCallbackId {
        PkU32InsertCallbackId(self.imp.on_insert(Box::new(callback)))
    }

    fn remove_on_insert(&self, callback: PkU32InsertCallbackId) {
        self.imp.remove_on_insert(callback.0)
    }

    type DeleteCallbackId = PkU32DeleteCallbackId;

    fn on_delete(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row) + Send + 'static,
    ) -> PkU32DeleteCallbackId {
        PkU32DeleteCallbackId(self.imp.on_delete(Box::new(callback)))
    }

    fn remove_on_delete(&self, callback: PkU32DeleteCallbackId) {
        self.imp.remove_on_delete(callback.0)
    }
}

#[doc(hidden)]
pub(super) fn register_table(client_cache: &mut __sdk::ClientCache<super::RemoteModule>) {
    let _table = client_cache.get_or_make_table::<PkU32>("pk_u32");
    _table.add_unique_constraint::<u32>("n", |row| &row.n);
}
pub struct PkU32UpdateCallbackId(__sdk::CallbackId);

impl<'ctx> __sdk::TableWithPrimaryKey for PkU32TableHandle<'ctx> {
    type UpdateCallbackId = PkU32UpdateCallbackId;

    fn on_update(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row, &Self::Row) + Send + 'static,
    ) -> PkU32UpdateCallbackId {
        PkU32UpdateCallbackId(self.imp.on_update(Box::new(callback)))
    }

    fn remove_on_update(&self, callback: PkU32UpdateCallbackId) {
        self.imp.remove_on_update(callback.0)
    }
}

#[doc(hidden)]
pub(super) fn parse_table_update(
    raw_updates: __ws::TableUpdate<__ws::BsatnFormat>,
) -> __sdk::Result<__sdk::TableUpdate<PkU32>> {
    __sdk::TableUpdate::parse_table_update(raw_updates).map_err(|e| {
        __sdk::InternalError::failed_parse("TableUpdate<PkU32>", "TableUpdate")
            .with_cause(e)
            .into()
    })
}

/// Access to the `n` unique index on the table `pk_u32`,
/// which allows point queries on the field of the same name
/// via the [`PkU32NUnique::find`] method.
///
/// Users are encouraged not to explicitly reference this type,
/// but to directly chain method calls,
/// like `ctx.db.pk_u_32().n().find(...)`.
pub struct PkU32NUnique<'ctx> {
    imp: __sdk::UniqueConstraintHandle<PkU32, u32>,
    phantom: std::marker::PhantomData<&'ctx super::RemoteTables>,
}

impl<'ctx> PkU32TableHandle<'ctx> {
    /// Get a handle on the `n` unique index on the table `pk_u32`.
    pub fn n(&self) -> PkU32NUnique<'ctx> {
        PkU32NUnique {
            imp: self.imp.get_unique_constraint::<u32>("n"),
            phantom: std::marker::PhantomData,
        }
    }
}

impl<'ctx> PkU32NUnique<'ctx> {
    /// Find the subscribed row whose `n` column value is equal to `col_val`,
    /// if such a row is present in the client cache.
    pub fn find(&self, col_val: &u32) -> Option<PkU32> {
        self.imp.find(col_val)
    }
}
