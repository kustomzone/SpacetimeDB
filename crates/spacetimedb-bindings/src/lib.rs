pub mod args;
pub mod buffer;
mod data_key;
pub mod hash;
mod primary_key;
mod type_def;
mod type_value;

pub use data_key::DataKey;
pub use hash::Hash;
pub use primary_key::PrimaryKey;
use std::alloc::{alloc as _alloc, dealloc as _dealloc, Layout};
use std::ops::Range;
use std::panic;
pub use type_def::{ElementDef, TupleDef, TypeDef};
pub use type_value::{EqTypeValue, RangeTypeValue, TupleValue, TypeValue};

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

extern "C" {
    fn _create_table(table_id: u32, ptr: *mut u8);
    fn _create_index(table_id: u32, col_id: u32, index_type: u8);

    fn _insert(table_id: u32, ptr: *mut u8);

    fn _delete_pk(table_id: u32, ptr: *mut u8) -> u8;
    fn _delete_value(table_id: u32, ptr: *mut u8) -> u8;
    fn _delete_eq(table_id: u32, col_id: u32, ptr: *mut u8) -> i32;
    fn _delete_range(table_id: u32, col_id: u32, ptr: *mut u8) -> i32;

    fn _filter_eq(table_id: u32, col_id: u32, src_ptr: *mut u8, result_ptr: *mut u8);

    fn _iter(table_id: u32) -> u64;
    fn _console_log(level: u8, ptr: *const u8, len: u32);
}

// TODO: probably do something lighter weight here
#[no_mangle]
extern "C" fn __init_panic__() {
    panic::set_hook(Box::new(panic_hook));
}

fn panic_hook(info: &panic::PanicInfo) {
    let msg = info.to_string();
    eprintln!("{}", msg);
}

#[doc(hidden)]
pub fn _console_log_debug(string: &str) {
    let s = string.as_bytes();
    let ptr = s.as_ptr();
    unsafe {
        _console_log(3, ptr, s.len() as u32);
    }
}

#[doc(hidden)]
pub fn _console_log_info(string: &str) {
    let s = string.as_bytes();
    let ptr = s.as_ptr();
    unsafe {
        _console_log(2, ptr, s.len() as u32);
    }
}

#[doc(hidden)]
pub fn _console_log_warn(string: &str) {
    let s = string.as_bytes();
    let ptr = s.as_ptr();
    unsafe {
        _console_log(1, ptr, s.len() as u32);
    }
}

#[doc(hidden)]
pub fn _console_log_error(string: &str) {
    let s = string.as_bytes();
    let ptr = s.as_ptr();
    unsafe {
        _console_log(0, ptr, s.len() as u32);
    }
}

#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => ($crate::_console_log_info(&format!($($arg)*)))
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::_console_log_info(&format!($($arg)*)))
}

#[macro_export]
macro_rules! eprintln {
    ($($arg:tt)*) => ($crate::_console_log_error(&format!($($arg)*)))
}

#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => ($crate::_console_log_error(&format!($($arg)*)))
}

#[macro_export]
macro_rules! dbg {
    // NOTE: We cannot use `concat!` to make a static string as a format argument
    // of `eprintln!` because `file!` could contain a `{` or
    // `$val` expression could be a block (`{ .. }`), in which case the `eprintln!`
    // will be malformed.
    () => {
        $crate::eprintln!("[{}:{}]", file!(), line!())
    };
    ($val:expr $(,)?) => {
        // Use of `match` here is intentional because it affects the lifetimes
        // of temporaries - https://stackoverflow.com/a/48732525/1063961
        match $val {
            tmp => {
                $crate::eprintln!("[{}:{}] {} = {:#?}",
                    file!(), line!(), stringify!($val), &tmp);
                tmp
            }
        }
    };
    ($($val:expr),+ $(,)?) => {
        ($($crate::dbg!($val)),+,)
    };
}

const ROW_BUF_LEN: usize = 1024;
static mut ROW_BUF: Option<*mut u8> = None;

#[no_mangle]
extern "C" fn alloc(size: usize) -> *mut u8 {
    let align = std::mem::align_of::<usize>();
    unsafe {
        let layout = Layout::from_size_align_unchecked(size, align);
        _alloc(layout)
    }
}

#[no_mangle]
extern "C" fn dealloc(ptr: *mut u8, size: usize) {
    let align = std::mem::align_of::<usize>();
    unsafe {
        let layout = Layout::from_size_align_unchecked(size, align);
        _dealloc(ptr, layout);
    }
}

unsafe fn row_buf() -> *mut u8 {
    if ROW_BUF.is_none() {
        let ptr = alloc(ROW_BUF_LEN);
        ROW_BUF = Some(ptr);
    }
    ROW_BUF.unwrap()
}

pub fn encode_row(row: TupleValue, bytes: &mut Vec<u8>) {
    row.encode(bytes);
}

pub fn decode_row(schema: &TupleDef, bytes: &mut &[u8]) -> (Result<TupleValue, &'static str>, usize) {
    TupleValue::decode(schema, bytes)
}

pub fn encode_schema(schema: TupleDef, bytes: &mut Vec<u8>) {
    schema.encode(bytes);
}

pub fn decode_schema(bytes: &mut &[u8]) -> (Result<TupleDef, String>, usize) {
    TupleDef::decode(bytes)
}

pub fn create_table(table_id: u32, table_name: &str, schema: TupleDef) {
    unsafe {
        let ptr = row_buf();

        let mut schema_bytes = Vec::new();
        schema.encode(&mut schema_bytes);

        let table_info = TupleValue {
            elements: vec![
                TypeValue::String(table_name.to_string()),
                TypeValue::Bytes(schema_bytes),
            ],
        };

        let mut bytes = Vec::from_raw_parts(ptr, 0, ROW_BUF_LEN);
        table_info.encode(&mut bytes);

        std::mem::forget(bytes);
        _create_table(table_id, ptr);
    }
}

pub fn insert(table_id: u32, row: TupleValue) {
    unsafe {
        let ptr = row_buf();
        let mut bytes = Vec::from_raw_parts(ptr, 0, ROW_BUF_LEN);
        row.encode(&mut bytes);
        std::mem::forget(bytes);
        _insert(table_id, ptr);
    }
}

pub fn delete_pk(table_id: u32, primary_key: PrimaryKey) -> Option<usize> {
    let result = unsafe {
        let ptr = row_buf();
        let mut bytes = Vec::from_raw_parts(ptr, 0, ROW_BUF_LEN);
        primary_key.encode(&mut bytes);
        std::mem::forget(bytes);
        _delete_pk(table_id, ptr)
    };
    if result == 0 {
        return None;
    }
    return Some(1);
}

pub fn delete_filter<F: Fn(&TupleValue) -> bool>(table_id: u32, f: F) -> Option<usize> {
    let mut count = 0;
    for tuple_value in __iter__(table_id).unwrap() {
        if f(&tuple_value) {
            count += 1;
            unsafe {
                let ptr = row_buf();
                let mut bytes = Vec::from_raw_parts(ptr, 0, ROW_BUF_LEN);
                tuple_value.encode(&mut bytes);
                if _delete_value(table_id, ptr) == 0 {
                    panic!("Something ain't right.");
                }
            }
        }
    }
    Some(count)
}

pub fn delete_eq(table_id: u32, col_id: u32, eq_value: EqTypeValue) -> Option<usize> {
    let result = unsafe {
        let ptr = row_buf();
        let mut bytes = Vec::from_raw_parts(ptr, 0, ROW_BUF_LEN);
        eq_value.encode(&mut bytes);
        _delete_eq(table_id, col_id, ptr)
    };
    if result == -1 {
        return None;
    }
    return Some(result as usize);
}

pub fn delete_range(table_id: u32, col_id: u32, range: Range<RangeTypeValue>) -> Option<usize> {
    let result = unsafe {
        let ptr = row_buf();
        let mut bytes = Vec::from_raw_parts(ptr, 0, ROW_BUF_LEN);
        let start = TypeValue::from(range.start);
        let end = TypeValue::from(range.end);
        let tuple = TupleValue {
            elements: vec![start, end],
        };
        tuple.encode(&mut bytes);
        _delete_range(table_id, col_id, ptr)
    };
    if result == -1 {
        return None;
    }
    return Some(result as usize);
}

pub fn create_index(_table_id: u32, _index_type: u8, _col_ids: Vec<u32>) {}

// TODO: going to have to somehow ensure TypeValue is equatable
pub fn filter_eq(_table_id: u32, _col_id: u32, _eq_value: TypeValue) -> Option<TupleValue> {
    return None;
}

//
// fn page_table(table_id : u32, pager_token : u32, read_entries : u32) {
//
// }

pub fn __iter__(table_id: u32) -> Option<TableIter> {
    let data = unsafe { _iter(table_id) };
    let ptr = (data >> 32) as u32 as *mut u8;
    let size = data as u32;
    let bytes: Vec<u8> = unsafe { Vec::from_raw_parts(ptr, size as usize, size as usize) };

    let slice = &mut &bytes[..];
    let initial_size = slice.len() as u32;
    let (schema, schema_size) = decode_schema(slice);
    if let Err(e) = schema {
        panic!("__iter__: Could not decode schema. Err: {}", e);
    }

    let data_size = (slice.len() - schema_size) as u32;
    let start_ptr = ptr;
    let data_ptr = unsafe { start_ptr.add(schema_size as usize) };

    std::mem::forget(bytes);
    Some(TableIter {
        start_ptr,
        initial_size,
        ptr: data_ptr,
        size: data_size,
        schema: schema.unwrap(),
    })
}

pub struct TableIter {
    start_ptr: *mut u8,
    initial_size: u32,
    ptr: *mut u8,
    size: u32,
    schema: TupleDef,
}

impl Iterator for TableIter {
    type Item = TupleValue;

    fn next(&mut self) -> Option<Self::Item> {
        let bytes: Vec<u8> = unsafe { Vec::from_raw_parts(self.ptr, self.size as usize, self.size as usize) };
        let slice = &mut &bytes[..];
        if slice.len() > 0 {
            let (row, num_read) = decode_row(&self.schema, slice);
            if let Err(e) = row {
                panic!("TableIter::next: Failed to decode row! Err: {}", e);
            }
            self.ptr = unsafe { self.ptr.add(num_read) };
            self.size = self.size - num_read as u32;
            std::mem::forget(bytes);
            return Some(row.unwrap());
        }
        // TODO: potential memory leak if they don't read all the stuff, figure out how to do this
        std::mem::forget(bytes);
        dealloc(self.start_ptr, self.initial_size as usize);
        return None;
    }
}
