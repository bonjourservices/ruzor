use crate::Result;
use crate::engines::{DigestDatabase, Record};
use crate::error::PyzorError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MySqlDsn {
    pub host: String,
    pub user: String,
    pub password: String,
    pub database: String,
    pub table: String,
}

impl MySqlDsn {
    pub fn parse(value: &str) -> Result<Self> {
        let parts = value.split(',').collect::<Vec<_>>();
        if parts.len() != 5 {
            return Err(PyzorError::Comm(
                "MySQL DSN must be host,user,password,db,table".to_string(),
            ));
        }
        Ok(Self {
            host: parts[0].to_string(),
            user: parts[1].to_string(),
            password: parts[2].to_string(),
            database: parts[3].to_string(),
            table: parts[4].to_string(),
        })
    }

    pub fn statements(&self) -> MySqlStatements {
        MySqlStatements::new(&self.table)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MySqlStatements {
    table: String,
}

impl MySqlStatements {
    pub fn new(table: impl Into<String>) -> Self {
        Self {
            table: table.into(),
        }
    }

    pub fn iter_keys(&self) -> String {
        format!("SELECT digest FROM {}", self.table)
    }

    pub fn iter_items(&self) -> String {
        format!(
            "SELECT digest, r_count, wl_count, r_entered, r_updated, wl_entered, wl_updated FROM {}",
            self.table
        )
    }

    pub fn select_record(&self) -> String {
        format!(
            "SELECT r_count, wl_count, r_entered, r_updated, wl_entered, wl_updated FROM {} WHERE digest=%s",
            self.table
        )
    }

    pub fn report(&self) -> String {
        format!(
            "INSERT INTO {} (digest, r_count, wl_count, r_entered, r_updated, wl_entered, wl_updated) VALUES (%s, 1, 0, NOW(), NOW(), NOW(), NOW()) ON DUPLICATE KEY UPDATE r_count=r_count+1, r_updated=NOW()",
            self.table
        )
    }

    pub fn whitelist(&self) -> String {
        format!(
            "INSERT INTO {} (digest, r_count, wl_count, r_entered, r_updated, wl_entered, wl_updated) VALUES (%s, 0, 1, NOW(), NOW(), NOW(), NOW()) ON DUPLICATE KEY UPDATE wl_count=wl_count+1, wl_updated=NOW()",
            self.table
        )
    }

    pub fn set_record(&self) -> String {
        format!(
            "INSERT INTO {} (digest, r_count, wl_count, r_entered, r_updated, wl_entered, wl_updated) VALUES (%s, %s, %s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE r_count=%s, wl_count=%s, r_entered=%s, r_updated=%s, wl_entered=%s, wl_updated=%s",
            self.table
        )
    }

    pub fn delete_record(&self) -> String {
        format!("DELETE FROM {} WHERE digest=%s", self.table)
    }

    pub fn reorganize(&self) -> String {
        format!("DELETE FROM {} WHERE r_updated<%s", self.table)
    }

    pub fn select_record_prepared(&self) -> String {
        mysql_prepared_placeholders(&self.select_record())
    }

    pub fn report_prepared(&self) -> String {
        mysql_prepared_placeholders(&self.report())
    }

    pub fn whitelist_prepared(&self) -> String {
        mysql_prepared_placeholders(&self.whitelist())
    }

    pub fn set_record_prepared(&self) -> String {
        mysql_prepared_placeholders(&self.set_record())
    }
}

pub trait MySqlExecutor: Send {
    fn fetch_record(&mut self, statement: &str, digest: &str) -> Result<Option<Record>>;
    fn execute_digest_batch(&mut self, statement: &str, digests: &[String]) -> Result<()>;
    fn execute_set_record(&mut self, statement: &str, digest: &str, record: &Record) -> Result<()>;
}

#[derive(Debug)]
pub struct MySqlDatabase<E> {
    statements: MySqlStatements,
    executor: E,
}

impl<E> MySqlDatabase<E> {
    pub fn with_executor(dsn: MySqlDsn, executor: E) -> Self {
        Self {
            statements: dsn.statements(),
            executor,
        }
    }

    pub fn statements(&self) -> &MySqlStatements {
        &self.statements
    }
}

impl<E: MySqlExecutor> DigestDatabase for MySqlDatabase<E> {
    fn get(&mut self, digest: &str) -> Result<Record> {
        self.executor
            .fetch_record(&self.statements.select_record_prepared(), digest)
            .map(|record| record.unwrap_or_default())
    }

    fn set(&mut self, digest: &str, record: Record) -> Result<()> {
        self.executor
            .execute_set_record(&self.statements.set_record_prepared(), digest, &record)
    }

    fn report(&mut self, digests: &[String]) -> Result<()> {
        self.executor
            .execute_digest_batch(&self.statements.report_prepared(), digests)
    }

    fn whitelist(&mut self, digests: &[String]) -> Result<()> {
        self.executor
            .execute_digest_batch(&self.statements.whitelist_prepared(), digests)
    }
}

fn mysql_prepared_placeholders(statement: &str) -> String {
    statement.replace("%s", "?")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn mysql_dsn_matches_reference_split_order() {
        let dsn = MySqlDsn::parse("localhost,pyzor,secret,pyzord,public").unwrap();

        assert_eq!(dsn.host, "localhost");
        assert_eq!(dsn.user, "pyzor");
        assert_eq!(dsn.password, "secret");
        assert_eq!(dsn.database, "pyzord");
        assert_eq!(dsn.table, "public");
        assert!(MySqlDsn::parse("localhost,pyzor,secret,pyzord").is_err());
        assert!(MySqlDsn::parse("localhost,pyzor,secret,pyzord,public,extra").is_err());
    }

    #[test]
    fn mysql_sql_templates_match_reference_engine_operations() {
        let statements = MySqlStatements::new("public");

        assert_eq!(statements.iter_keys(), "SELECT digest FROM public");
        assert_eq!(
            statements.iter_items(),
            "SELECT digest, r_count, wl_count, r_entered, r_updated, wl_entered, wl_updated FROM public"
        );
        assert_eq!(
            statements.select_record(),
            "SELECT r_count, wl_count, r_entered, r_updated, wl_entered, wl_updated FROM public WHERE digest=%s"
        );
        assert_eq!(
            statements.report(),
            "INSERT INTO public (digest, r_count, wl_count, r_entered, r_updated, wl_entered, wl_updated) VALUES (%s, 1, 0, NOW(), NOW(), NOW(), NOW()) ON DUPLICATE KEY UPDATE r_count=r_count+1, r_updated=NOW()"
        );
        assert_eq!(
            statements.whitelist(),
            "INSERT INTO public (digest, r_count, wl_count, r_entered, r_updated, wl_entered, wl_updated) VALUES (%s, 0, 1, NOW(), NOW(), NOW(), NOW()) ON DUPLICATE KEY UPDATE wl_count=wl_count+1, wl_updated=NOW()"
        );
        assert_eq!(
            statements.set_record(),
            "INSERT INTO public (digest, r_count, wl_count, r_entered, r_updated, wl_entered, wl_updated) VALUES (%s, %s, %s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE r_count=%s, wl_count=%s, r_entered=%s, r_updated=%s, wl_entered=%s, wl_updated=%s"
        );
        assert_eq!(
            statements.delete_record(),
            "DELETE FROM public WHERE digest=%s"
        );
        assert_eq!(
            statements.reorganize(),
            "DELETE FROM public WHERE r_updated<%s"
        );
    }

    #[test]
    fn mysql_prepared_templates_use_rust_driver_placeholders() {
        let statements = MySqlStatements::new("public");

        assert_eq!(
            statements.select_record_prepared(),
            "SELECT r_count, wl_count, r_entered, r_updated, wl_entered, wl_updated FROM public WHERE digest=?"
        );
        assert_eq!(
            statements.report_prepared(),
            "INSERT INTO public (digest, r_count, wl_count, r_entered, r_updated, wl_entered, wl_updated) VALUES (?, 1, 0, NOW(), NOW(), NOW(), NOW()) ON DUPLICATE KEY UPDATE r_count=r_count+1, r_updated=NOW()"
        );
        assert_eq!(
            statements.whitelist_prepared(),
            "INSERT INTO public (digest, r_count, wl_count, r_entered, r_updated, wl_entered, wl_updated) VALUES (?, 0, 1, NOW(), NOW(), NOW(), NOW()) ON DUPLICATE KEY UPDATE wl_count=wl_count+1, wl_updated=NOW()"
        );
        assert_eq!(
            statements.set_record_prepared(),
            "INSERT INTO public (digest, r_count, wl_count, r_entered, r_updated, wl_entered, wl_updated) VALUES (?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE r_count=?, wl_count=?, r_entered=?, r_updated=?, wl_entered=?, wl_updated=?"
        );
    }

    #[test]
    fn mysql_database_adapter_uses_one_step_reference_operations() {
        let dsn = MySqlDsn::parse("localhost,pyzor,secret,pyzord,public").unwrap();
        let mut db = MySqlDatabase::with_executor(dsn, FakeExecutor::default());
        let digest = "7421216f915a87e02da034cc483f5c876e1a1338";

        assert_eq!(db.get(digest).unwrap(), Record::default());

        db.report(&[digest.to_string(), digest.to_string()])
            .unwrap();
        assert_eq!(db.get(digest).unwrap().r_count, 2);

        db.whitelist(&[digest.to_string()]).unwrap();
        let record = db.get(digest).unwrap();
        assert_eq!(record.r_count, 2);
        assert_eq!(record.wl_count, 1);

        db.set(
            digest,
            Record {
                r_count: 24,
                wl_count: 42,
                r_entered: Some(1_400_221_786),
                r_updated: Some(1_400_221_794),
                wl_entered: Some(1_400_221_800),
                wl_updated: Some(1_400_221_900),
            },
        )
        .unwrap();
        assert_eq!(db.get(digest).unwrap().r_count, 24);
        assert_eq!(db.get(digest).unwrap().wl_count, 42);
    }

    #[derive(Default)]
    struct FakeExecutor {
        records: HashMap<String, Record>,
    }

    impl MySqlExecutor for FakeExecutor {
        fn fetch_record(&mut self, statement: &str, digest: &str) -> Result<Option<Record>> {
            assert_eq!(
                statement,
                "SELECT r_count, wl_count, r_entered, r_updated, wl_entered, wl_updated FROM public WHERE digest=?"
            );
            Ok(self.records.get(digest).cloned())
        }

        fn execute_digest_batch(&mut self, statement: &str, digests: &[String]) -> Result<()> {
            for digest in digests {
                let record = self.records.entry(digest.clone()).or_default();
                match statement {
                    "INSERT INTO public (digest, r_count, wl_count, r_entered, r_updated, wl_entered, wl_updated) VALUES (?, 1, 0, NOW(), NOW(), NOW(), NOW()) ON DUPLICATE KEY UPDATE r_count=r_count+1, r_updated=NOW()" =>
                    {
                        record.r_increment();
                    }
                    "INSERT INTO public (digest, r_count, wl_count, r_entered, r_updated, wl_entered, wl_updated) VALUES (?, 0, 1, NOW(), NOW(), NOW(), NOW()) ON DUPLICATE KEY UPDATE wl_count=wl_count+1, wl_updated=NOW()" =>
                    {
                        record.wl_increment();
                    }
                    other => panic!("unexpected MySQL batch statement: {other}"),
                }
            }
            Ok(())
        }

        fn execute_set_record(
            &mut self,
            statement: &str,
            digest: &str,
            record: &Record,
        ) -> Result<()> {
            assert_eq!(
                statement,
                "INSERT INTO public (digest, r_count, wl_count, r_entered, r_updated, wl_entered, wl_updated) VALUES (?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE r_count=?, wl_count=?, r_entered=?, r_updated=?, wl_entered=?, wl_updated=?"
            );
            self.records.insert(digest.to_string(), record.clone());
            Ok(())
        }
    }
}
