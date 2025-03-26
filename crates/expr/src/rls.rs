use spacetimedb_lib::identity::AuthCtx;
use spacetimedb_primitives::TableId;
use spacetimedb_sql_parser::ast::BinOp;

use crate::{
    check::{parse_and_type_sub, SchemaView},
    expr::{Expr, FieldProject, LeftDeepJoin, ProjectName, RelExpr, Relvar},
};

/// This utility is responsible for implementing view resolution.
///
/// What is view resolution and why do we need it?
///
/// A view is a named query that can be referenced as though it were just a regular table.
/// In SpacetimeDB, Row Level Security (RLS) is implemented using views.
/// We must resolve/expand these views in order to guarantee the correct access controls.
///
/// How is it implemented?
///
/// Take the following join tree for example:
/// ```text
///     x
///    / \
///   x   c
///  / \
/// a   b
/// ```
///
/// Let's assume b is a view with the following structure:
/// ```text
///     x
///    / \
///   x   f
///  / \
/// d   e
/// ```
///
/// Logically we just want to expand the tree like so:
/// ```text
///     x
///    / \
///   x   c
///  / \
/// a   x
///    / \
///   x   f
///  / \
/// d   e
/// ```
///
/// However the join trees at this level are left deep.
/// To maintain this invariant, the correct expansion would be:
/// ```text
///         x
///        / \
///       x   c
///      / \
///     x   f
///    / \
///   x   e
///  / \
/// a   d
/// ```
///
/// That is, the subtree whose root is the left sibling of the node being expanded,
/// i.e. the subtree rooted at `a` in the above example,
/// must be pushed below the leftmost leaf node of the view expansion.
pub fn resolve_views(
    tx: &impl SchemaView,
    expr: ProjectName,
    auth: &AuthCtx,
    has_param: &mut bool,
) -> anyhow::Result<Vec<ProjectName>> {
    // RLS does not apply to the database owner
    if auth.caller == auth.owner {
        return Ok(vec![expr]);
    }

    let Some(return_name) = expr.return_name().map(|name| name.to_owned().into_boxed_str()) else {
        anyhow::bail!("Could not determine return type during RLS resolution")
    };

    // Unwrap the underlying `RelExpr`
    let expr = match expr {
        ProjectName::None(expr) | ProjectName::Some(expr, _) => expr,
    };

    // The expanded fragments could be join trees, so wrap each of them in an outer project.
    resolve_views_for_expr(tx, expr, None, &mut 0, &mut vec![], has_param, auth).map(|fragments| {
        fragments
            .into_iter()
            .map(|expr| ProjectName::Some(expr, return_name.clone()))
            .collect()
    })
}

/// The main driver for view resolution. See [resolve_views] for details.
///
/// But first, a word on the `return_table_id` parameter.
///
/// Why do we care about it?
/// What does it mean for it to be `None`?
///
/// If this IS NOT a user query, it must be a view definition.
/// In SpacetimeDB this means we're expanding an RLS filter.
/// RLS filters cannot be self-referential, meaning that within a filter,
/// we cannot recursively expand references to its return table.
///
/// However, a `None` value implies that this expression is a user query,
/// and so we should attempt to expand references to the return table.
fn resolve_views_for_expr(
    tx: &impl SchemaView,
    view: RelExpr,
    return_table_id: Option<TableId>,
    suffix: &mut usize,
    resolving: &mut Vec<TableId>,
    has_param: &mut bool,
    auth: &AuthCtx,
) -> anyhow::Result<Vec<RelExpr>> {
    let is_return_table = |relvar: &Relvar| return_table_id.is_some_and(|id| relvar.schema.table_id == id);

    // Collect the table ids queried by this view.
    // Ignore the id of the return table, since RLS views cannot be recursive.
    let mut names = vec![];
    view.visit(&mut |expr| match expr {
        RelExpr::RelVar(rhs)
        | RelExpr::LeftDeepJoin(LeftDeepJoin { rhs, .. })
        | RelExpr::EqJoin(LeftDeepJoin { rhs, .. }, ..)
            if !is_return_table(rhs) =>
        {
            names.push((rhs.schema.table_id, rhs.alias.clone()));
        }
        _ => {}
    });

    // Are we currently resolving any of them?
    if names.iter().any(|(table_id, _)| resolving.contains(table_id)) {
        anyhow::bail!("Discovered cycle when resolving RLS rules");
    }

    let return_name = |expr: &ProjectName| {
        expr.return_name()
            .map(|name| name.to_owned())
            .ok_or_else(|| anyhow::anyhow!("Could not resolve table reference in RLS filter"))
    };

    let mut view_def_fragments = vec![];

    for (table_id, alias) in names {
        let mut view_fragments = vec![];

        for sql in tx.rls_rules_for_table(table_id)? {
            // Parse and type check the RLS filter
            let (expr, is_parameterized) = parse_and_type_sub(&sql, tx, auth)?;

            // Are any of the RLS rules parameterized?
            *has_param = *has_param || is_parameterized;

            // We need to know which alias is being returned for alpha-renaming
            let return_name = return_name(&expr)?;

            // Unwrap the underlying `RelExpr`
            let expr = match expr {
                ProjectName::None(expr) | ProjectName::Some(expr, _) => expr,
            };

            resolving.push(table_id);

            // Resolve views within the RLS filter itself
            let fragments = resolve_views_for_expr(tx, expr, Some(table_id), suffix, resolving, has_param, auth)?;

            resolving.pop();

            // Run alpha conversion on each view definition
            for mut fragment in fragments {
                *suffix += 1;
                alpha_rename(&mut fragment, &mut |name: &str| {
                    if name == return_name {
                        return alias.clone();
                    }
                    (name.to_owned() + "_" + &suffix.to_string()).into_boxed_str()
                });

                view_fragments.push(fragment);
            }
        }

        if !view_fragments.is_empty() {
            view_def_fragments.push((table_id, alias, view_fragments));
        }
    }

    /// After we collect all the necessary view definitions and run alpha conversion,
    /// this function handles the actual replacement of the view with its definition.
    fn expand_views(expr: RelExpr, view_def_fragments: &[(TableId, Box<str>, Vec<RelExpr>)], out: &mut Vec<RelExpr>) {
        match view_def_fragments {
            [] => out.push(expr),
            [(table_id, alias, fragments), view_def_fragments @ ..] => {
                for fragment in fragments {
                    let expanded = expand_leaf(expr.clone(), *table_id, alias, fragment);
                    expand_views(expanded, view_def_fragments, out);
                }
            }
        }
    }

    let mut resolved = vec![];
    expand_views(view, &view_def_fragments, &mut resolved);
    Ok(resolved)
}

/// When expanding a view, we must do an alpha conversion on the view definition.
/// This involves renaming the table aliases before replacing the view reference.
fn alpha_rename(expr: &mut RelExpr, f: &mut impl FnMut(&str) -> Box<str>) {
    /// Helper for renaming a relvar
    fn rename(relvar: &mut Relvar, f: &mut impl FnMut(&str) -> Box<str>) {
        relvar.alias = f(&relvar.alias);
    }
    /// Helper for renaming a field reference
    fn rename_field(field: &mut FieldProject, f: &mut impl FnMut(&str) -> Box<str>) {
        field.table = f(&field.table);
    }
    expr.visit_mut(&mut |expr| match expr {
        RelExpr::RelVar(rhs) | RelExpr::LeftDeepJoin(LeftDeepJoin { rhs, .. }) => {
            rename(rhs, f);
        }
        RelExpr::EqJoin(LeftDeepJoin { rhs, .. }, a, b) => {
            rename(rhs, f);
            rename_field(a, f);
            rename_field(b, f);
        }
        RelExpr::Select(_, expr) => {
            expr.visit_mut(&mut |expr| {
                if let Expr::Field(field) = expr {
                    rename_field(field, f);
                }
            });
        }
    });
}

/// Extends a left deep join tree with another.
///
/// Ex.
///
/// Assume `expr` is given by:
/// ```text
///     x
///    / \
///   x   f
///  / \
/// d   e
/// ```
///
/// Assume `with` is given by:
/// ```text
///     x
///    / \
///   x   c
///  / \
/// a   b
/// ```
///
/// This function extends `expr` by pushing `with` to the left-most leaf node:
/// ```text
///           x
///          / \
///         x   f
///        / \
///       x   e
///      / \
///     x   d
///    / \
///   x   c
///  / \
/// a   b
/// ```
fn extend_lhs(expr: RelExpr, with: RelExpr) -> RelExpr {
    match expr {
        RelExpr::RelVar(rhs) => RelExpr::LeftDeepJoin(LeftDeepJoin {
            lhs: Box::new(with),
            rhs,
        }),
        RelExpr::Select(input, expr) => RelExpr::Select(Box::new(extend_lhs(*input, with)), expr),
        RelExpr::LeftDeepJoin(join) => RelExpr::LeftDeepJoin(LeftDeepJoin {
            lhs: Box::new(extend_lhs(*join.lhs, with)),
            ..join
        }),
        RelExpr::EqJoin(join, a, b) => RelExpr::EqJoin(
            LeftDeepJoin {
                lhs: Box::new(extend_lhs(*join.lhs, with)),
                ..join
            },
            a,
            b,
        ),
    }
}

/// Replaces the leaf node determined by `table_id` and `alias` with the subtree `with`.
/// Ensures the expanded tree stays left deep.
fn expand_leaf(expr: RelExpr, table_id: TableId, alias: &str, with: &RelExpr) -> RelExpr {
    let ok = |relvar: &Relvar| relvar.schema.table_id == table_id && relvar.alias.as_ref() == alias;
    match expr {
        RelExpr::RelVar(relvar, ..) if ok(&relvar) => with.clone(),
        RelExpr::RelVar(..) => expr,
        RelExpr::Select(input, expr) => RelExpr::Select(Box::new(expand_leaf(*input, table_id, alias, with)), expr),
        RelExpr::LeftDeepJoin(join) if ok(&join.rhs) => extend_lhs(with.clone(), *join.lhs),
        RelExpr::LeftDeepJoin(LeftDeepJoin { lhs, rhs }) => RelExpr::LeftDeepJoin(LeftDeepJoin {
            lhs: Box::new(expand_leaf(*lhs, table_id, alias, with)),
            rhs,
        }),
        RelExpr::EqJoin(join, a, b) if ok(&join.rhs) => RelExpr::Select(
            Box::new(extend_lhs(with.clone(), *join.lhs)),
            Expr::BinOp(BinOp::Eq, Box::new(Expr::Field(a)), Box::new(Expr::Field(b))),
        ),
        RelExpr::EqJoin(LeftDeepJoin { lhs, rhs }, a, b) => RelExpr::EqJoin(
            LeftDeepJoin {
                lhs: Box::new(expand_leaf(*lhs, table_id, alias, with)),
                rhs,
            },
            a,
            b,
        ),
    }
}
