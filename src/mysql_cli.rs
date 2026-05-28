use std::process::Command;

use crate::Result;
use crate::account::now_timestamp;
use crate::engines::Record;
use crate::error::PyzorError;
use crate::local_time;
use crate::mysql_engine::{MySqlDatabase, MySqlDsn, MySqlExecutor};

const MYSQL_UNAVAILABLE: &str = "Database temporarily unavailable.";

#[derive(Clone, Debug)]
pub struct MySqlCommandExecutor {
    dsn: MySqlDsn,
    program: String,
}

impl MySqlCommandExecutor {
    pub fn new(dsn: MySqlDsn) -> Self {
        let program = std::env::var("PYZOR_MYSQL_BIN").unwrap_or_else(|_| "mysql".to_string());
        Self::with_program(dsn, program)
    }

    pub fn with_program(dsn: MySqlDsn, program: impl Into<String>) -> Self {
        Self {
            dsn,
            program: program.into(),
        }
    }

    pub fn command_args(&self, sql: &str) -> Vec<String> {
        let mut args = vec![
            "--batch".to_string(),
            "--raw".to_string(),
            "--skip-column-names".to_string(),
        ];
        if self.dsn.host.starts_with('/') {
            args.push(format!("--socket={}", self.dsn.host));
        } else if !self.dsn.host.is_empty() {
            args.push(format!("--host={}", self.dsn.host));
        }
        if !self.dsn.user.is_empty() {
            args.push(format!("--user={}", self.dsn.user));
        }
        if !self.dsn.password.is_empty() {
            args.push(format!("--password={}", self.dsn.password));
        }
        if !self.dsn.database.is_empty() {
            args.push(format!("--database={}", self.dsn.database));
        }
        args.push("--execute".to_string());
        args.push(sql.to_string());
        args
    }

    pub fn execute_statement(&self, sql: &str) -> Result<String> {
        let output = Command::new(&self.program)
            .args(self.command_args(sql))
            .output()
            .map_err(|error| {
                PyzorError::Comm(format!(
                    "Unable to run mysql client '{}': {}",
                    self.program, error
                ))
            })?;
        if !output.status.success() {
            return Err(database_unavailable());
        }
        String::from_utf8(output.stdout)
            .map_err(|error| PyzorError::Comm(format!("Invalid mysql output: {error}")))
    }
}

impl MySqlDatabase<MySqlCommandExecutor> {
    pub fn connect(dsn: impl AsRef<str>) -> Result<Self> {
        Self::connect_with_max_age(dsn, None)
    }

    pub fn connect_with_max_age(dsn: impl AsRef<str>, max_age: Option<i64>) -> Result<Self> {
        Self::connect_with_max_age_and_db_connections(dsn, max_age, 0)
    }

    pub fn connect_with_max_age_and_db_connections(
        dsn: impl AsRef<str>,
        max_age: Option<i64>,
        _db_connections: usize,
    ) -> Result<Self> {
        let dsn = MySqlDsn::parse(dsn.as_ref())?;
        let statements = dsn.statements();
        let executor = MySqlCommandExecutor::new(dsn.clone());
        executor.execute_statement("SELECT 1")?;
        if let Some(max_age) = max_age.filter(|age| *age != 0) {
            let cutoff = now_timestamp() - max_age;
            let statement = mysql_prepared_placeholders(&statements.reorganize());
            let sql = bind_statement(&statement, &[SqlValue::DateTime(Some(cutoff))])?;
            executor.execute_statement(&sql)?;
        }
        Ok(MySqlDatabase::with_executor(dsn, executor))
    }
}

impl MySqlExecutor for MySqlCommandExecutor {
    fn fetch_record(&mut self, statement: &str, digest: &str) -> Result<Option<Record>> {
        let sql = bind_statement(statement, &[SqlValue::Text(digest)])?;
        let output = self.execute_statement(&sql)?;
        output
            .lines()
            .find(|line| !line.trim().is_empty())
            .map(parse_record_row)
            .transpose()
    }

    fn execute_digest_batch(&mut self, statement: &str, digests: &[String]) -> Result<()> {
        let mut sql = String::new();
        for digest in digests {
            if !sql.is_empty() {
                sql.push(';');
            }
            sql.push_str(&bind_statement(statement, &[SqlValue::Text(digest)])?);
        }
        if sql.is_empty() {
            return Ok(());
        }
        self.execute_statement(&sql).map(|_| ())
    }

    fn execute_set_record(&mut self, statement: &str, digest: &str, record: &Record) -> Result<()> {
        let values = [
            SqlValue::Text(digest),
            SqlValue::Integer(record.r_count),
            SqlValue::Integer(record.wl_count),
            SqlValue::DateTime(record.r_entered),
            SqlValue::DateTime(record.r_updated),
            SqlValue::DateTime(record.wl_entered),
            SqlValue::DateTime(record.wl_updated),
            SqlValue::Integer(record.r_count),
            SqlValue::Integer(record.wl_count),
            SqlValue::DateTime(record.r_entered),
            SqlValue::DateTime(record.r_updated),
            SqlValue::DateTime(record.wl_entered),
            SqlValue::DateTime(record.wl_updated),
        ];
        let sql = bind_statement(statement, &values)?;
        self.execute_statement(&sql).map(|_| ())
    }
}

#[derive(Clone, Copy, Debug)]
enum SqlValue<'a> {
    Text(&'a str),
    Integer(i64),
    DateTime(Option<i64>),
}

impl SqlValue<'_> {
    fn to_sql(self) -> String {
        match self {
            Self::Text(value) => quote_sql_string(value),
            Self::Integer(value) => value.to_string(),
            Self::DateTime(Some(value)) => quote_sql_string(&format_mysql_datetime(value)),
            Self::DateTime(None) => "NULL".to_string(),
        }
    }
}

fn bind_statement(statement: &str, values: &[SqlValue<'_>]) -> Result<String> {
    let mut bound = String::with_capacity(statement.len() + values.len() * 16);
    let mut values = values.iter();
    for ch in statement.chars() {
        if ch == '?' {
            let value = values.next().ok_or_else(|| {
                PyzorError::Comm("Missing MySQL statement parameter.".to_string())
            })?;
            bound.push_str(&value.to_sql());
        } else {
            bound.push(ch);
        }
    }
    if values.next().is_some() {
        return Err(PyzorError::Comm(
            "Too many MySQL statement parameters.".to_string(),
        ));
    }
    Ok(bound)
}

fn mysql_prepared_placeholders(statement: &str) -> String {
    statement.replace("%s", "?")
}

fn quote_sql_string(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for ch in value.chars() {
        match ch {
            '\0' => quoted.push_str("\\0"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\\' => quoted.push_str("\\\\"),
            '\'' => quoted.push_str("\\'"),
            '"' => quoted.push_str("\\\""),
            '\x1a' => quoted.push_str("\\Z"),
            _ => quoted.push(ch),
        }
    }
    quoted.push('\'');
    quoted
}

fn parse_record_row(row: &str) -> Result<Record> {
    let fields = row.split('\t').collect::<Vec<_>>();
    if fields.len() != 6 {
        return Err(database_unavailable());
    }
    Ok(Record {
        r_count: parse_nullable_i64(fields[0])?.unwrap_or(0),
        wl_count: parse_nullable_i64(fields[1])?.unwrap_or(0),
        r_entered: parse_mysql_datetime(fields[2])?,
        r_updated: parse_mysql_datetime(fields[3])?,
        wl_entered: parse_mysql_datetime(fields[4])?,
        wl_updated: parse_mysql_datetime(fields[5])?,
    })
}

fn parse_nullable_i64(value: &str) -> Result<Option<i64>> {
    if is_mysql_null(value) {
        return Ok(None);
    }
    value.parse().map(Some).map_err(|_| database_unavailable())
}

fn parse_mysql_datetime(value: &str) -> Result<Option<i64>> {
    if is_mysql_null(value) {
        return Ok(None);
    }
    local_time::parse_datetime(value)
        .map(Some)
        .ok_or_else(database_unavailable)
}

fn is_mysql_null(value: &str) -> bool {
    value.eq_ignore_ascii_case("NULL") || value == "\\N" || value.is_empty()
}

fn format_mysql_datetime(timestamp: i64) -> String {
    local_time::format_timestamp(timestamp)
}

fn database_unavailable() -> PyzorError {
    PyzorError::Comm(MYSQL_UNAVAILABLE.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mysql_command_args_use_reference_dsn_fields() {
        let dsn = MySqlDsn::parse("localhost,pyzor,secret,pyzord,public").unwrap();
        let executor = MySqlCommandExecutor::with_program(dsn, "mysql");

        assert_eq!(
            executor.command_args("SELECT 1"),
            vec![
                "--batch",
                "--raw",
                "--skip-column-names",
                "--host=localhost",
                "--user=pyzor",
                "--password=secret",
                "--database=pyzord",
                "--execute",
                "SELECT 1"
            ]
        );
    }

    #[test]
    fn mysql_command_args_support_unix_socket_hosts() {
        let dsn = MySqlDsn::parse("/tmp/mysql.sock,pyzor,,pyzord,public").unwrap();
        let executor = MySqlCommandExecutor::with_program(dsn, "mysql");

        assert!(
            executor
                .command_args("SELECT 1")
                .contains(&"--socket=/tmp/mysql.sock".to_string())
        );
    }

    #[test]
    fn mysql_statement_binding_quotes_values_and_times() {
        crate::local_time::with_timezone_for_tests("UTC", || {
            let statement = "INSERT INTO public VALUES (?, ?, ?, ?)";
            let sql = bind_statement(
                statement,
                &[
                    SqlValue::Text("abc'd\\e"),
                    SqlValue::Integer(24),
                    SqlValue::DateTime(Some(1_400_221_786)),
                    SqlValue::DateTime(None),
                ],
            )
            .unwrap();

            assert_eq!(
                sql,
                "INSERT INTO public VALUES ('abc\\'d\\\\e', 24, '2014-05-16 06:29:46', NULL)"
            );
        });
    }

    #[test]
    fn mysql_datetime_binding_and_parsing_use_python_local_time() {
        crate::local_time::with_timezone_for_tests("Europe/Paris", || {
            let sql = bind_statement(
                "DELETE FROM public WHERE r_updated<?",
                &[SqlValue::DateTime(Some(1_400_221_786))],
            )
            .unwrap();

            assert_eq!(
                sql,
                "DELETE FROM public WHERE r_updated<'2014-05-16 08:29:46'"
            );
            assert_eq!(
                parse_mysql_datetime("2014-05-16 08:29:46").unwrap(),
                Some(1_400_221_786)
            );
        });
    }

    #[test]
    fn mysql_statement_binding_rejects_placeholder_mismatch() {
        assert!(bind_statement("SELECT ?", &[]).is_err());
        assert!(bind_statement("SELECT 1", &[SqlValue::Integer(1)]).is_err());
    }

    #[test]
    fn mysql_row_parser_matches_reference_column_order() {
        crate::local_time::with_timezone_for_tests("UTC", || {
            let row = "24\t42\t2014-05-16 06:29:46\t2014-05-16 06:29:54\tNULL\t\\N";

            assert_eq!(
                parse_record_row(row).unwrap(),
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
}
