// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN RUST INSTEAD.

#![allow(unused)]
use super::one_f_64_type::OneF64;
use spacetimedb_sdk::__codegen::{
    self as __sdk, __lib, __sats, __ws,
    anyhow::{self as __anyhow, Context as _},
};

/// Table handle for the table `one_f64`.
///
/// Obtain a handle from the [`OneF64TableAccess::one_f_64`] method on [`super::RemoteTables`],
/// like `ctx.db.one_f_64()`.
///
/// Users are encouraged not to explicitly reference this type,
/// but to directly chain method calls,
/// like `ctx.db.one_f_64().on_insert(...)`.
pub struct OneF64TableHandle<'ctx> {
    imp: __sdk::TableHandle<OneF64>,
    ctx: std::marker::PhantomData<&'ctx super::RemoteTables>,
}

#[allow(non_camel_case_types)]
/// Extension trait for access to the table `one_f64`.
///
/// Implemented for [`super::RemoteTables`].
pub trait OneF64TableAccess {
    #[allow(non_snake_case)]
    /// Obtain a [`OneF64TableHandle`], which mediates access to the table `one_f64`.
    fn one_f_64(&self) -> OneF64TableHandle<'_>;
}

impl OneF64TableAccess for super::RemoteTables {
    fn one_f_64(&self) -> OneF64TableHandle<'_> {
        OneF64TableHandle {
            imp: self.imp.get_table::<OneF64>("one_f64"),
            ctx: std::marker::PhantomData,
        }
    }
}

pub struct OneF64InsertCallbackId(__sdk::CallbackId);
pub struct OneF64DeleteCallbackId(__sdk::CallbackId);

impl<'ctx> __sdk::Table for OneF64TableHandle<'ctx> {
    type Row = OneF64;
    type EventContext = super::EventContext;

    fn count(&self) -> u64 {
        self.imp.count()
    }
    fn iter(&self) -> impl Iterator<Item = OneF64> + '_ {
        self.imp.iter()
    }

    type InsertCallbackId = OneF64InsertCallbackId;

    fn on_insert(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row) + Send + 'static,
    ) -> OneF64InsertCallbackId {
        OneF64InsertCallbackId(self.imp.on_insert(Box::new(callback)))
    }

    fn remove_on_insert(&self, callback: OneF64InsertCallbackId) {
        self.imp.remove_on_insert(callback.0)
    }

    type DeleteCallbackId = OneF64DeleteCallbackId;

    fn on_delete(
        &self,
        callback: impl FnMut(&Self::EventContext, &Self::Row) + Send + 'static,
    ) -> OneF64DeleteCallbackId {
        OneF64DeleteCallbackId(self.imp.on_delete(Box::new(callback)))
    }

    fn remove_on_delete(&self, callback: OneF64DeleteCallbackId) {
        self.imp.remove_on_delete(callback.0)
    }
}

#[doc(hidden)]
pub(super) fn register_table(client_cache: &mut __sdk::ClientCache<super::RemoteModule>) {
    let _table = client_cache.get_or_make_table::<OneF64>("one_f64");
}
#[doc(hidden)]
pub(super) fn parse_table_update(
    raw_updates: __ws::TableUpdate<__ws::BsatnFormat>,
) -> __anyhow::Result<__sdk::TableUpdate<OneF64>> {
    __sdk::TableUpdate::parse_table_update_no_primary_key(raw_updates)
        .context("Failed to parse table update for table \"one_f64\"")
}
