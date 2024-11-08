// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN RUST INSTEAD.

#![allow(unused)]
use super::one_string_type::OneString;
use spacetimedb_sdk::{
    self as __sdk,
    anyhow::{self as __anyhow, Context as _},
    lib as __lib, sats as __sats, ws_messages as __ws,
};

/// Table handle for the table `one_string`.
///
/// Obtain a handle from the [`OneStringTableAccess::one_string`] method on [`super::RemoteTables`],
/// like `ctx.db.one_string()`.
///
/// Users are encouraged not to explicitly reference this type,
/// but to directly chain method calls,
/// like `ctx.db.one_string().on_insert(...)`.
pub struct OneStringTableHandle<'ctx> {
    imp: __sdk::db_connection::TableHandle<OneString>,
    ctx: std::marker::PhantomData<&'ctx super::RemoteTables>,
}

#[allow(non_camel_case_types)]
/// Extension trait for access to the table `one_string`.
///
/// Implemented for [`super::RemoteTables`].
pub trait OneStringTableAccess {
    #[allow(non_snake_case)]
    /// Obtain a [`OneStringTableHandle`], which mediates access to the table `one_string`.
    fn one_string(&self) -> OneStringTableHandle<'_>;
}

impl OneStringTableAccess for super::RemoteTables {
    fn one_string(&self) -> OneStringTableHandle<'_> {
        OneStringTableHandle {
            imp: self.imp.get_table::<OneString>("one_string"),
            ctx: std::marker::PhantomData,
        }
    }
}

pub struct OneStringInsertCallbackId(__sdk::callbacks::CallbackId);
pub struct OneStringDeleteCallbackId(__sdk::callbacks::CallbackId);

impl<'ctx> __sdk::table::Table for OneStringTableHandle<'ctx> {
    type Row = OneString;
    type EventContext = super::EventContext;

    fn count(&self) -> u64 {
        self.imp.count()
    }
    fn iter(&self) -> impl Iterator<Item = OneString> + '_ {
        self.imp.iter()
    }

    type InsertCallbackId = OneStringInsertCallbackId;

    fn on_insert(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row) + Send + 'static,
    ) -> OneStringInsertCallbackId {
        OneStringInsertCallbackId(self.imp.on_insert(Box::new(callback)))
    }

    fn remove_on_insert(&self, callback: OneStringInsertCallbackId) {
        self.imp.remove_on_insert(callback.0)
    }

    type DeleteCallbackId = OneStringDeleteCallbackId;

    fn on_delete(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row) + Send + 'static,
    ) -> OneStringDeleteCallbackId {
        OneStringDeleteCallbackId(self.imp.on_delete(Box::new(callback)))
    }

    fn remove_on_delete(&self, callback: OneStringDeleteCallbackId) {
        self.imp.remove_on_delete(callback.0)
    }
}

#[doc(hidden)]
pub(super) fn parse_table_update(
    raw_updates: __ws::TableUpdate<__ws::BsatnFormat>,
) -> __anyhow::Result<__sdk::spacetime_module::TableUpdate<OneString>> {
    __sdk::spacetime_module::TableUpdate::parse_table_update_no_primary_key(raw_updates)
        .context("Failed to parse table update for table \"one_string\"")
}
