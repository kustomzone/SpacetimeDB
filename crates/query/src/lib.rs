use anyhow::{bail, Result};
use spacetimedb_execution::{
    dml::{MutDatastore, MutExecutor},
    pipelined::ProjectListExecutor,
    Datastore, DeltaStore,
};
use spacetimedb_expr::{
    check::{parse_and_type_sub, SchemaView},
    expr::{AggType, ProjectList},
    rls::{resolve_views, resolve_views_for_expr},
    statement::{parse_and_type_sql, Statement, DML},
};
use spacetimedb_lib::{identity::AuthCtx, metrics::ExecutionMetrics, ProductValue};
use spacetimedb_physical_plan::{
    compile::{compile_dml_plan, compile_select, compile_select_list},
    plan::{ProjectListPlan, ProjectPlan},
};
use spacetimedb_primitives::TableId;

/// DIRTY HACK ALERT: Maximum allowed length, in UTF-8 bytes, of SQL queries.
/// Any query longer than this will be rejected.
/// This prevents a stack overflow when compiling queries with deeply-nested `AND` and `OR` conditions.
const MAX_SQL_LENGTH: usize = 50_000;

pub fn compile_subscription(
    sql: &str,
    tx: &impl SchemaView,
    auth: &AuthCtx,
) -> Result<(Vec<ProjectPlan>, TableId, Box<str>, bool)> {
    if sql.len() > MAX_SQL_LENGTH {
        bail!("SQL query exceeds maximum allowed length: \"{sql:.120}...\"")
    }

    let (plan, mut has_param) = parse_and_type_sub(sql, tx, auth)?;

    let Some(return_id) = plan.return_table_id() else {
        bail!("Failed to determine TableId for query")
    };

    let Some(return_name) = tx.schema_for_table(return_id).map(|schema| schema.table_name.clone()) else {
        bail!("TableId `{return_id}` does not exist")
    };

    // Resolve any RLS filters
    let plan_fragments = resolve_views(tx, plan, auth, &mut has_param)?
        .into_iter()
        .map(compile_select)
        .collect();

    Ok((plan_fragments, return_id, return_name, has_param))
}

/// A utility for parsing and type checking a sql statement
pub fn compile_sql_stmt(sql: &str, tx: &impl SchemaView, auth: &AuthCtx) -> Result<Statement> {
    if sql.len() > MAX_SQL_LENGTH {
        bail!("SQL query exceeds maximum allowed length: \"{sql:.120}...\"")
    }

    fn resolve_views_for_sql(expr: ProjectList, tx: &impl SchemaView, auth: &AuthCtx) -> Result<ProjectList> {
        match expr {
            ProjectList::Name(exprs) => {
                let mut plan_fragments = vec![];
                for expr in exprs {
                    plan_fragments.extend(resolve_views(tx, expr, auth, &mut false)?);
                }
                Ok(ProjectList::Name(plan_fragments))
            }
            ProjectList::List(exprs, fields) => {
                let mut plan_fragments = vec![];
                for expr in exprs {
                    plan_fragments.extend(resolve_views_for_expr(
                        tx,
                        expr,
                        None,
                        &mut 0,
                        &mut vec![],
                        &mut false,
                        auth,
                    )?);
                }
                Ok(ProjectList::List(plan_fragments, fields))
            }
            ProjectList::Limit(expr, n) => Ok(ProjectList::Limit(Box::new(resolve_views_for_sql(*expr, tx, auth)?), n)),
            ProjectList::Agg(exprs, AggType::Count, name, ty) => {
                let mut plan_fragments = vec![];
                for expr in exprs {
                    plan_fragments.extend(resolve_views_for_expr(
                        tx,
                        expr,
                        None,
                        &mut 0,
                        &mut vec![],
                        &mut false,
                        auth,
                    )?);
                }
                Ok(ProjectList::Agg(plan_fragments, AggType::Count, name, ty))
            }
        }
    }

    match parse_and_type_sql(sql, tx, auth)? {
        stmt @ Statement::DML(_) => Ok(stmt),
        Statement::Select(expr) => Ok(Statement::Select(resolve_views_for_sql(expr, tx, auth)?)),
    }
}

/// A utility for executing a sql select statement
pub fn execute_select_stmt<Tx: Datastore + DeltaStore>(
    stmt: ProjectList,
    tx: &Tx,
    metrics: &mut ExecutionMetrics,
    check_row_limit: impl Fn(ProjectListPlan) -> Result<ProjectListPlan>,
) -> Result<Vec<ProductValue>> {
    let plan = compile_select_list(stmt).optimize()?;
    let plan = check_row_limit(plan)?;
    let plan = ProjectListExecutor::from(plan);
    let mut rows = vec![];
    plan.execute(tx, metrics, &mut |row| {
        rows.push(row);
        Ok(())
    })?;
    Ok(rows)
}

/// A utility for executing a sql dml statement
pub fn execute_dml_stmt<Tx: MutDatastore>(stmt: DML, tx: &mut Tx, metrics: &mut ExecutionMetrics) -> Result<()> {
    let plan = compile_dml_plan(stmt).optimize()?;
    let plan = MutExecutor::from(plan);
    plan.execute(tx, metrics)
}
