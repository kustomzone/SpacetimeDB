// THIS FILE IS AUTOMATICALLY GENERATED BY SPACETIMEDB. EDITS TO THIS FILE
// WILL NOT BE SAVED. MODIFY TABLES IN RUST INSTEAD.

#![allow(unused)]
use spacetimedb_sdk::__codegen::{
    self as __sdk, __lib, __sats, __ws,
    anyhow::{self as __anyhow, Context as _},
};

#[derive(__lib::ser::Serialize, __lib::de::Deserialize, Clone, PartialEq, Debug)]
#[sats(crate = __lib)]
pub struct EveryVecStruct {
    pub a: Vec<u8>,
    pub b: Vec<u16>,
    pub c: Vec<u32>,
    pub d: Vec<u64>,
    pub e: Vec<u128>,
    pub f: Vec<__sats::u256>,
    pub g: Vec<i8>,
    pub h: Vec<i16>,
    pub i: Vec<i32>,
    pub j: Vec<i64>,
    pub k: Vec<i128>,
    pub l: Vec<__sats::i256>,
    pub m: Vec<bool>,
    pub n: Vec<f32>,
    pub o: Vec<f64>,
    pub p: Vec<String>,
    pub q: Vec<__sdk::Identity>,
    pub r: Vec<__sdk::Address>,
    pub s: Vec<__sdk::Timestamp>,
    pub t: Vec<__sdk::TimeDuration>,
}

impl __sdk::InModule for EveryVecStruct {
    type Module = super::RemoteModule;
}
