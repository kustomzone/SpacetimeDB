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
pub struct VecF32 {
    pub f: Vec<f32>,
}

impl TableType for VecF32 {
    const TABLE_NAME: &'static str = "VecF32";
    type ReducerEvent = super::ReducerEvent;
}

impl VecF32 {
    #[allow(unused)]
    pub fn filter_by_f(f: Vec<f32>) -> TableIter<Self> {
        Self::filter(|row| row.f == f)
    }
}
