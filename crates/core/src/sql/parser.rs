use crate::db::datastore::locking_tx_datastore::MutTxId;
use crate::db::relational_db::RelationalDB;
use crate::sql::ast::SchemaViewer;
use spacetimedb_expr::check::parse_and_type_sub;
use spacetimedb_expr::errors::TypingError;
use spacetimedb_expr::expr::RelExpr;
use spacetimedb_expr::ty::TyCtx;
use spacetimedb_lib::db::raw_def::v9::RawRowLevelSecurityDefV9;
use spacetimedb_lib::identity::AuthCtx;
use spacetimedb_schema::schema::RowLevelSecuritySchema;

pub struct RowLevelExpr {
    pub sql: RelExpr,
    pub def: RowLevelSecuritySchema,
}

impl RowLevelExpr {
    pub fn build_row_level_expr(
        stdb: &RelationalDB,
        tx: &mut MutTxId,
        auth_ctx: &AuthCtx,
        rls: &RawRowLevelSecurityDefV9,
    ) -> Result<Self, TypingError> {
        let mut ctx = TyCtx::default();
        let sql = parse_and_type_sub(&mut ctx, &rls.sql, &SchemaViewer::new(stdb, tx, auth_ctx))?;

        Ok(Self {
            def: RowLevelSecuritySchema {
                table_id: sql.table_id(&mut ctx)?,
                sql: rls.sql.clone(),
            },
            sql,
        })
    }
}
