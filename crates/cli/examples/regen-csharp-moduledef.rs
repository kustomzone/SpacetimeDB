//! This script is used to generate the C# bindings for the `RawModuleDef` type.
//! Run `cargo run --example regen-csharp-moduledef` to update C# bindings whenever the module definition changes.

use fs_err as fs;
use regex::Regex;
use spacetimedb_cli::generate::{csharp, generate};
use spacetimedb_lib::{RawModuleDef, RawModuleDefV8};
use std::path::Path;
use std::sync::OnceLock;

macro_rules! regex_replace {
    ($value:expr, $re:expr, $replace:expr) => {{
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new($re).unwrap())
            .replace_all($value, $replace)
    }};
}

fn main() -> anyhow::Result<()> {
    let module = RawModuleDefV8::with_builder(|module| {
        module.add_type::<RawModuleDef>();
    });

    let dir = &Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../bindings-csharp/Runtime/Internal/Autogen"
    ))
    .canonicalize()?;

    fs::remove_dir_all(dir)?;
    fs::create_dir(dir)?;

    generate(
        RawModuleDef::V8BackCompat(module),
        &csharp::Csharp {
            namespace: "SpacetimeDB.Internal",
        },
    )?
    .into_iter()
    .map(|(filename, code)| {
        // Skip anything but raw types (in particular, this will skip top-level SpacetimeDBClient.g.cs which we don't need).
        let Some(filename) = filename.strip_prefix("Types/") else {
            return Ok(());
        };

        // Someday we might replace custom BSATN types with autogenerated ones as well,
        // but for now they're not very large and our copies are somewhat more optimised.
        //
        // Ignore those types and replace their references with our own with plain old regexes.
        if filename == "AlgebraicType.g.cs" || filename.starts_with("SumType") || filename.starts_with("ProductType") {
            return Ok(());
        }

        let code = regex_replace!(&code, r"\bAlgebraicType\b", "SpacetimeDB.BSATN.$0");
        let code = regex_replace!(
            &code,
            r"\b(ProductTypeElement|SumTypeVariant)\b",
            "SpacetimeDB.BSATN.AggregateElement"
        );
        let code = regex_replace!(
            &code,
            r"\b(Product|Sum)Type\b",
            "List<SpacetimeDB.BSATN.AggregateElement>"
        );

        fs::write(dir.join(filename), code.as_ref())
    })
    .collect::<std::io::Result<()>>()?;

    Ok(())
}
