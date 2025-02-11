// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN YOUR MODULE SOURCE CODE INSTEAD.

#![allow(unused, clippy::all)]
use super::pk_connection_id_type::PkConnectionId;
use spacetimedb_sdk::__codegen::{self as __sdk, __lib, __sats, __ws};

/// Table handle for the table `pk_connection_id`.
///
/// Obtain a handle from the [`PkConnectionIdTableAccess::pk_connection_id`] method on [`super::RemoteTables`],
/// like `ctx.db.pk_connection_id()`.
///
/// Users are encouraged not to explicitly reference this type,
/// but to directly chain method calls,
/// like `ctx.db.pk_connection_id().on_insert(...)`.
pub struct PkConnectionIdTableHandle<'ctx> {
    imp: __sdk::TableHandle<PkConnectionId>,
    ctx: std::marker::PhantomData<&'ctx super::RemoteTables>,
}

#[allow(non_camel_case_types)]
/// Extension trait for access to the table `pk_connection_id`.
///
/// Implemented for [`super::RemoteTables`].
pub trait PkConnectionIdTableAccess {
    #[allow(non_snake_case)]
    /// Obtain a [`PkConnectionIdTableHandle`], which mediates access to the table `pk_connection_id`.
    fn pk_connection_id(&self) -> PkConnectionIdTableHandle<'_>;
}

impl PkConnectionIdTableAccess for super::RemoteTables {
    fn pk_connection_id(&self) -> PkConnectionIdTableHandle<'_> {
        PkConnectionIdTableHandle {
            imp: self.imp.get_table::<PkConnectionId>("pk_connection_id"),
            ctx: std::marker::PhantomData,
        }
    }
}

pub struct PkConnectionIdInsertCallbackId(__sdk::CallbackId);
pub struct PkConnectionIdDeleteCallbackId(__sdk::CallbackId);

impl<'ctx> __sdk::Table for PkConnectionIdTableHandle<'ctx> {
    type Row = PkConnectionId;
    type EventContext = super::EventContext;

    fn count(&self) -> u64 {
        self.imp.count()
    }
    fn iter(&self) -> impl Iterator<Item = PkConnectionId> + '_ {
        self.imp.iter()
    }

    type InsertCallbackId = PkConnectionIdInsertCallbackId;

    fn on_insert(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row) + Send + 'static,
    ) -> PkConnectionIdInsertCallbackId {
        PkConnectionIdInsertCallbackId(self.imp.on_insert(Box::new(callback)))
    }

    fn remove_on_insert(&self, callback: PkConnectionIdInsertCallbackId) {
        self.imp.remove_on_insert(callback.0)
    }

    type DeleteCallbackId = PkConnectionIdDeleteCallbackId;

    fn on_delete(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row) + Send + 'static,
    ) -> PkConnectionIdDeleteCallbackId {
        PkConnectionIdDeleteCallbackId(self.imp.on_delete(Box::new(callback)))
    }

    fn remove_on_delete(&self, callback: PkConnectionIdDeleteCallbackId) {
        self.imp.remove_on_delete(callback.0)
    }
}

#[doc(hidden)]
pub(super) fn register_table(client_cache: &mut __sdk::ClientCache<super::RemoteModule>) {
    let _table = client_cache.get_or_make_table::<PkConnectionId>("pk_connection_id");
    _table.add_unique_constraint::<__sdk::ConnectionId>("a", |row| &row.a);
}
pub struct PkConnectionIdUpdateCallbackId(__sdk::CallbackId);

impl<'ctx> __sdk::TableWithPrimaryKey for PkConnectionIdTableHandle<'ctx> {
    type UpdateCallbackId = PkConnectionIdUpdateCallbackId;

    fn on_update(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row, &Self::Row) + Send + 'static,
    ) -> PkConnectionIdUpdateCallbackId {
        PkConnectionIdUpdateCallbackId(self.imp.on_update(Box::new(callback)))
    }

    fn remove_on_update(&self, callback: PkConnectionIdUpdateCallbackId) {
        self.imp.remove_on_update(callback.0)
    }
}

#[doc(hidden)]
pub(super) fn parse_table_update(
    raw_updates: __ws::TableUpdate<__ws::BsatnFormat>,
) -> __sdk::Result<__sdk::TableUpdate<PkConnectionId>> {
    __sdk::TableUpdate::parse_table_update_with_primary_key::<__sdk::ConnectionId>(
        raw_updates,
        |row: &PkConnectionId| &row.a,
    )
    .map_err(|e| {
        __sdk::InternalError::failed_parse("TableUpdate<PkConnectionId>", "TableUpdate")
            .with_cause(e)
            .into()
    })
}

/// Access to the `a` unique index on the table `pk_connection_id`,
/// which allows point queries on the field of the same name
/// via the [`PkConnectionIdAUnique::find`] method.
///
/// Users are encouraged not to explicitly reference this type,
/// but to directly chain method calls,
/// like `ctx.db.pk_connection_id().a().find(...)`.
pub struct PkConnectionIdAUnique<'ctx> {
    imp: __sdk::UniqueConstraintHandle<PkConnectionId, __sdk::ConnectionId>,
    phantom: std::marker::PhantomData<&'ctx super::RemoteTables>,
}

impl<'ctx> PkConnectionIdTableHandle<'ctx> {
    /// Get a handle on the `a` unique index on the table `pk_connection_id`.
    pub fn a(&self) -> PkConnectionIdAUnique<'ctx> {
        PkConnectionIdAUnique {
            imp: self.imp.get_unique_constraint::<__sdk::ConnectionId>("a"),
            phantom: std::marker::PhantomData,
        }
    }
}

impl<'ctx> PkConnectionIdAUnique<'ctx> {
    /// Find the subscribed row whose `a` column value is equal to `col_val`,
    /// if such a row is present in the client cache.
    pub fn find(&self, col_val: &__sdk::ConnectionId) -> Option<PkConnectionId> {
        self.imp.find(col_val)
    }
}
