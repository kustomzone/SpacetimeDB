// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN RUST INSTEAD.

#![allow(unused_imports)]
use spacetimedb_sdk::{
    anyhow::{anyhow, Result},
    identity::Identity,
    reducer::{Reducer, ReducerCallbackId, Status},
    sats::{de::Deserialize, ser::Serialize},
    spacetimedb_lib,
    table::{TableIter, TableType, TableWithPrimaryKey},
    Address,
};

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct OneString {
    pub s: String,
}

impl TableType for OneString {
    const TABLE_NAME: &'static str = "OneString";
    type ReducerEvent = super::ReducerEvent;
}

impl OneString {
    #[allow(unused)]
    pub fn filter_by_s(s: String) -> TableIter<Self> {
        Self::filter(|row| row.s == s)
    }
}
