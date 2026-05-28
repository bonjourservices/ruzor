use crate::Result;
use crate::account::now_timestamp;
use crate::engines::Record;
use crate::error::PyzorError;
use crate::local_time;
use crate::mysql_engine::{MySqlDatabase, MySqlDsn, MySqlExecutor};

use mysql::prelude::Queryable;
use mysql::{OptsBuilder, Pool, PoolConstraints, PoolOpts, Row, Value};

const MYSQL_UNAVAILABLE: &str = "Database temporarily unavailable.";

#[derive(Clone)]
pub struct MySqlNativeExecutor {
    pool: Pool,
}

impl MySqlNativeExecutor {
    pub fn new(dsn: MySqlDsn) -> Result<Self> {
        Self::new_with_db_connections(dsn, 0)
    }

    pub fn new_with_db_connections(dsn: MySqlDsn, db_connections: usize) -> Result<Self> {
        let pool = Pool::new(opts_from_dsn_with_db_connections(&dsn, db_connections))
            .map_err(mysql_failure)?;
        let executor = Self { pool };
        executor.ping()?;
        Ok(executor)
    }

    fn ping(&self) -> Result<()> {
        let mut conn = self.pool.get_conn().map_err(mysql_failure)?;
        conn.query_drop("SELECT 1").map_err(mysql_failure)
    }
}

impl std::fmt::Debug for MySqlNativeExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MySqlNativeExecutor { pool: ... }")
    }
}

impl MySqlDatabase<MySqlNativeExecutor> {
    pub fn connect(dsn: impl AsRef<str>) -> Result<Self> {
        Self::connect_with_max_age(dsn, None)
    }

    pub fn connect_with_max_age(dsn: impl AsRef<str>, max_age: Option<i64>) -> Result<Self> {
        Self::connect_with_max_age_and_db_connections(dsn, max_age, 0)
    }

    pub fn connect_with_max_age_and_db_connections(
        dsn: impl AsRef<str>,
        max_age: Option<i64>,
        db_connections: usize,
    ) -> Result<Self> {
        let dsn = MySqlDsn::parse(dsn.as_ref())?;
        let statements = dsn.statements();
        let mut executor =
            MySqlNativeExecutor::new_with_db_connections(dsn.clone(), db_connections)?;
        if let Some(max_age) = max_age.filter(|age| *age != 0) {
            let cutoff = now_timestamp() - max_age;
            executor.execute_delete_before(&statements.reorganize(), cutoff)?;
        }
        Ok(MySqlDatabase::with_executor(dsn, executor))
    }
}

impl MySqlNativeExecutor {
    fn execute_delete_before(&mut self, statement: &str, cutoff: i64) -> Result<()> {
        let mut conn = self.pool.get_conn().map_err(mysql_failure)?;
        conn.exec_drop(
            mysql_prepared_placeholders(statement),
            (mysql_datetime_value(Some(cutoff)),),
        )
        .map_err(mysql_failure)
    }
}

impl MySqlExecutor for MySqlNativeExecutor {
    fn fetch_record(&mut self, statement: &str, digest: &str) -> Result<Option<Record>> {
        let mut conn = self.pool.get_conn().map_err(mysql_failure)?;
        let row: Option<Row> = conn
            .exec_first(statement, (digest,))
            .map_err(mysql_failure)?;
        row.map(record_from_row).transpose()
    }

    fn execute_digest_batch(&mut self, statement: &str, digests: &[String]) -> Result<()> {
        if digests.is_empty() {
            return Ok(());
        }
        let mut conn = self.pool.get_conn().map_err(mysql_failure)?;
        conn.exec_batch(statement, digests.iter().map(|digest| (digest.as_str(),)))
            .map_err(mysql_failure)
    }

    fn execute_set_record(&mut self, statement: &str, digest: &str, record: &Record) -> Result<()> {
        let values = vec![
            Value::from(digest),
            Value::from(record.r_count),
            Value::from(record.wl_count),
            mysql_datetime_value(record.r_entered),
            mysql_datetime_value(record.r_updated),
            mysql_datetime_value(record.wl_entered),
            mysql_datetime_value(record.wl_updated),
            Value::from(record.r_count),
            Value::from(record.wl_count),
            mysql_datetime_value(record.r_entered),
            mysql_datetime_value(record.r_updated),
            mysql_datetime_value(record.wl_entered),
            mysql_datetime_value(record.wl_updated),
        ];
        let mut conn = self.pool.get_conn().map_err(mysql_failure)?;
        conn.exec_drop(statement, values).map_err(mysql_failure)
    }
}

fn opts_from_dsn_with_db_connections(dsn: &MySqlDsn, db_connections: usize) -> OptsBuilder {
    let mut opts = OptsBuilder::new()
        .user(non_empty(&dsn.user))
        .pass(non_empty(&dsn.password))
        .db_name(non_empty(&dsn.database));
    if dsn.host.starts_with('/') {
        opts = opts.socket(Some(dsn.host.clone())).prefer_socket(true);
    } else if !dsn.host.is_empty() {
        opts = opts
            .ip_or_hostname(Some(dsn.host.clone()))
            .prefer_socket(false);
    }
    if db_connections > 0
        && let Some(constraints) = PoolConstraints::new(db_connections, db_connections)
    {
        opts = opts.pool_opts(PoolOpts::default().with_constraints(constraints));
    }
    opts
}

fn non_empty(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn record_from_row(row: Row) -> Result<Record> {
    let values = row.unwrap();
    record_from_values(&values)
}

fn record_from_values(values: &[Value]) -> Result<Record> {
    if values.len() != 6 {
        return Err(database_unavailable());
    }
    Ok(Record {
        r_count: value_to_i64(&values[0])?.unwrap_or(0),
        wl_count: value_to_i64(&values[1])?.unwrap_or(0),
        r_entered: value_to_timestamp(&values[2])?,
        r_updated: value_to_timestamp(&values[3])?,
        wl_entered: value_to_timestamp(&values[4])?,
        wl_updated: value_to_timestamp(&values[5])?,
    })
}

fn value_to_i64(value: &Value) -> Result<Option<i64>> {
    match value {
        Value::NULL => Ok(None),
        Value::Int(value) => Ok(Some(*value)),
        Value::UInt(value) => (*value)
            .try_into()
            .map(Some)
            .map_err(|_| database_unavailable()),
        Value::Bytes(value) => {
            let value = std::str::from_utf8(value).map_err(|_| database_unavailable())?;
            if value.is_empty() {
                Ok(None)
            } else {
                value.parse().map(Some).map_err(|_| database_unavailable())
            }
        }
        _ => Err(database_unavailable()),
    }
}

fn value_to_timestamp(value: &Value) -> Result<Option<i64>> {
    match value {
        Value::NULL => Ok(None),
        Value::Date(year, month, day, hour, minute, second, _) => {
            parse_datetime_parts(*year, *month, *day, *hour, *minute, *second)
        }
        Value::Bytes(value) => {
            let value = std::str::from_utf8(value).map_err(|_| database_unavailable())?;
            if value.is_empty() {
                Ok(None)
            } else {
                local_time::parse_datetime(value)
                    .map(Some)
                    .ok_or_else(database_unavailable)
            }
        }
        _ => Err(database_unavailable()),
    }
}

fn parse_datetime_parts(
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
) -> Result<Option<i64>> {
    local_time::parse_datetime(&format!(
        "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}"
    ))
    .map(Some)
    .ok_or_else(database_unavailable)
}

fn mysql_datetime_value(timestamp: Option<i64>) -> Value {
    timestamp
        .map(|timestamp| Value::from(local_time::format_timestamp(timestamp)))
        .unwrap_or(Value::NULL)
}

fn mysql_prepared_placeholders(statement: &str) -> String {
    statement.replace("%s", "?")
}

fn mysql_failure(_error: mysql::Error) -> PyzorError {
    database_unavailable()
}

fn database_unavailable() -> PyzorError {
    PyzorError::Comm(MYSQL_UNAVAILABLE.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_mysql_record_values_match_reference_column_order() {
        crate::local_time::with_timezone_for_tests("UTC", || {
            let values = vec![
                Value::Int(24),
                Value::UInt(42),
                Value::Date(2014, 5, 16, 6, 29, 46, 0),
                Value::Bytes(b"2014-05-16 06:29:54".to_vec()),
                Value::NULL,
                Value::Bytes(Vec::new()),
            ];

            assert_eq!(
                record_from_values(&values).unwrap(),
                Record {
                    r_count: 24,
                    wl_count: 42,
                    r_entered: Some(1_400_221_786),
                    r_updated: Some(1_400_221_794),
                    wl_entered: None,
                    wl_updated: None,
                }
            );
        });
    }

    #[test]
    fn native_mysql_db_connections_sets_bounded_pool_constraints() {
        let dsn = MySqlDsn::parse("localhost,pyzor,secret,pyzord,public").unwrap();
        let opts: mysql::Opts = opts_from_dsn_with_db_connections(&dsn, 7).into();
        let constraints = opts.get_pool_opts().constraints();

        assert_eq!(constraints.min(), 7);
        assert_eq!(constraints.max(), 7);

        let opts: mysql::Opts = opts_from_dsn_with_db_connections(&dsn, 0).into();
        assert_eq!(
            opts.get_pool_opts().constraints(),
            PoolConstraints::default()
        );
    }

    #[test]
    fn native_mysql_datetime_params_use_python_local_time() {
        crate::local_time::with_timezone_for_tests("Europe/Paris", || {
            assert_eq!(
                mysql_datetime_value(Some(1_400_221_786)),
                Value::from("2014-05-16 08:29:46")
            );
            assert_eq!(mysql_datetime_value(None), Value::NULL);
        });
    }
}
