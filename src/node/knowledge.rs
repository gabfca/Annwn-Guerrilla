//! A module for handling node knowledge storage and retrieval using SQLite with caching.
//!
//! This module provides a [`NodeKnowledgeHandler`] struct that manages database connections,
//! executes SQL queries, and caches results for improved performance.

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Result as SqlResult;
use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    path::Path,
    sync::{Arc, RwLock},
};

/// The default filename for the knowledge database.
pub const KNOWLEDGE_DB_FILENAME: &str = "node_knowledge/knowledge.db";

/// A handler for managing node knowledge storage and retrieval.
///
/// This struct provides methods to execute and query SQL statements against a SQLite database,
/// with built-in connection pooling and query result caching.
#[derive(Clone)]
pub struct NodeKnowledgeHandler {
    /// Connection pool for database connections
    pool: Pool<SqliteConnectionManager>,
    /// Cache for query results, keyed by query hash
    cache: Arc<RwLock<HashMap<u64, Vec<HashMap<String, String>>>>>,
}

impl NodeKnowledgeHandler {
    /// Creates a new `NodeKnowledgeHandler` instance.
    ///
    /// # Returns
    ///
    /// A `SqlResult<Self>` containing the new handler or an error if initialization fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use node_knowledge::NodeKnowledgeHandler;
    ///
    /// let handler = NodeKnowledgeHandler::new().unwrap();
    /// ```
    pub fn new() -> SqlResult<Self> {
        if let Some(parent) = Path::new(KNOWLEDGE_DB_FILENAME).parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let manager = SqliteConnectionManager::file(KNOWLEDGE_DB_FILENAME);
        let pool = Pool::new(manager).unwrap();
        Ok(Self {
            pool,
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Executes a SQL statement without parameters.
    ///
    /// # Arguments
    ///
    /// * `sql` - The SQL statement to execute
    ///
    /// # Returns
    ///
    /// A `SqlResult<()>` indicating success or failure.
    ///
    /// # Note
    ///
    /// This will clear the query cache after execution.
    pub fn execute_sql(&self, sql: &str) -> SqlResult<()> {
        let conn = self
            .pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        conn.execute_batch(sql)?;
        self.clear_cache();
        Ok(())
    }

    /// Executes a SQL statement with parameters.
    ///
    /// # Arguments
    ///
    /// * `sql` - The SQL statement to execute
    /// * `params` - Parameters for the SQL statement
    ///
    /// # Returns
    ///
    /// A `SqlResult<()>` indicating success or failure.
    ///
    /// # Note
    ///
    /// This will clear the query cache after execution.
    pub fn execute_sql_params<P>(&self, sql: &str, params: P) -> SqlResult<()>
    where
        P: rusqlite::Params,
    {
        let conn = self
            .pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        conn.execute(sql, params)?;
        self.clear_cache();
        Ok(())
    }

    /// Queries the database with a SQL statement and parameters, returning results as a vector of HashMaps.
    ///
    /// Results are cached based on the SQL and parameters hash.
    ///
    /// # Arguments
    ///
    /// * `sql` - The SQL query to execute
    /// * `params` - Parameters for the SQL query
    ///
    /// # Returns
    ///
    /// A `SqlResult<Vec<HashMap<String, String>>>` containing the query results,
    /// where each row is represented as a HashMap of column names to values.
    pub fn query_sql_params<T>(
        &self,
        sql: &str,
        params: &[T],
    ) -> SqlResult<Vec<HashMap<String, String>>>
    where
        T: ToString + rusqlite::ToSql,
    {
        use rusqlite::types::ToSql;
        use std::collections::hash_map::DefaultHasher;

        let mut hasher = DefaultHasher::new();
        sql.hash(&mut hasher);
        for param in params {
            param.to_string().hash(&mut hasher);
        }
        let cache_key = hasher.finish();

        if let Some(cached) = self.cache.read().unwrap().get(&cache_key) {
            return Ok(cached.clone());
        }

        let conn = self
            .pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let mut stmt = conn.prepare(sql)?;
        let column_names = stmt
            .column_names()
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();

        let params_refs: Vec<&dyn ToSql> = params.iter().map(|p| p as &dyn ToSql).collect();

        let rows = stmt.query_map(&params_refs[..], |row| {
            let mut row_map = HashMap::with_capacity(column_names.len());
            for (i, col) in column_names.iter().enumerate() {
                if let Ok(val) = row.get::<_, String>(i) {
                    row_map.insert(col.clone(), val);
                }
            }
            Ok(row_map)
        })?;

        let results: Vec<_> = rows.filter_map(Result::ok).collect();

        self.cache
            .write()
            .unwrap()
            .insert(cache_key, results.clone());

        Ok(results)
    }

    /// Queries the database with a SQL statement without parameters.
    ///
    /// # Arguments
    ///
    /// * `sql` - The SQL query to execute
    ///
    /// # Returns
    ///
    /// A `SqlResult<Vec<HashMap<String, String>>>` containing the query results.
    pub fn query_sql(&self, sql: &str) -> SqlResult<Vec<HashMap<String, String>>> {
        self.query_sql_params::<String>(sql, &[])
    }

    /// Clears the query cache.
    pub fn clear_cache(&self) {
        self.cache.write().unwrap().clear();
    }
}