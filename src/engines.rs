use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::Result;
use crate::account::now_timestamp;
use crate::error::PyzorError;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Record {
    pub r_count: i64,
    pub wl_count: i64,
    pub r_entered: Option<i64>,
    pub r_updated: Option<i64>,
    pub wl_entered: Option<i64>,
    pub wl_updated: Option<i64>,
}

impl Record {
    pub fn r_increment(&mut self) {
        if self.r_count < isize::MAX as i64 {
            self.r_count += 1;
        }
        let now = now_timestamp();
        if self.r_entered.is_none() {
            self.r_entered = Some(now);
        }
        self.r_updated = Some(now);
    }

    pub fn wl_increment(&mut self) {
        if self.wl_count < isize::MAX as i64 {
            self.wl_count += 1;
        }
        let now = now_timestamp();
        if self.wl_entered.is_none() {
            self.wl_entered = Some(now);
        }
        self.wl_updated = Some(now);
    }
}

pub trait DigestDatabase: Send {
    fn get(&mut self, digest: &str) -> Result<Record>;
    fn set(&mut self, digest: &str, record: Record) -> Result<()>;
    fn report(&mut self, digests: &[String]) -> Result<()> {
        for digest in digests {
            let mut record = self.get(digest)?;
            record.r_increment();
            self.set(digest, record)?;
        }
        Ok(())
    }
    fn whitelist(&mut self, digests: &[String]) -> Result<()> {
        for digest in digests {
            let mut record = self.get(digest)?;
            record.wl_increment();
            self.set(digest, record)?;
        }
        Ok(())
    }
}

impl<T: DigestDatabase + ?Sized> DigestDatabase for Box<T> {
    fn get(&mut self, digest: &str) -> Result<Record> {
        (**self).get(digest)
    }

    fn set(&mut self, digest: &str, record: Record) -> Result<()> {
        (**self).set(digest, record)
    }

    fn report(&mut self, digests: &[String]) -> Result<()> {
        (**self).report(digests)
    }

    fn whitelist(&mut self, digests: &[String]) -> Result<()> {
        (**self).whitelist(digests)
    }
}

#[derive(Debug)]
pub struct FileDatabase {
    path: PathBuf,
    records: HashMap<String, Record>,
}

impl FileDatabase {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_cleanup_age(path, None)
    }

    pub fn open_with_cleanup_age(path: impl AsRef<Path>, cleanup_age: Option<i64>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut records = HashMap::new();
        if let Ok(text) = fs::read_to_string(&path) {
            for line in text.lines() {
                let Some((digest, encoded)) = line.split_once('\t') else {
                    continue;
                };
                if let Some(record) = decode_record(encoded) {
                    records.insert(digest.to_string(), record);
                }
            }
        }
        let mut db = Self { path, records };
        if let Some(cleanup_age) = cleanup_age.filter(|age| *age != 0) {
            db.reorganize(cleanup_age)?;
        }
        Ok(db)
    }

    pub fn get(&self, digest: &str) -> Record {
        self.records.get(digest).cloned().unwrap_or_default()
    }

    pub fn set(&mut self, digest: impl Into<String>, record: Record) -> Result<()> {
        self.records.insert(digest.into(), record);
        self.sync()
    }

    pub fn report(&mut self, digests: &[String]) -> Result<()> {
        for digest in digests {
            let mut record = FileDatabase::get(self, digest);
            record.r_increment();
            self.records.insert(digest.clone(), record);
        }
        self.sync()
    }

    pub fn whitelist(&mut self, digests: &[String]) -> Result<()> {
        for digest in digests {
            let mut record = FileDatabase::get(self, digest);
            record.wl_increment();
            self.records.insert(digest.clone(), record);
        }
        self.sync()
    }

    fn sync(&self) -> Result<()> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let mut rows: Vec<_> = self
            .records
            .iter()
            .map(|(digest, record)| format!("{}\t{}", digest, encode_record(record)))
            .collect();
        rows.sort();
        fs::write(&self.path, rows.join("\n")).map_err(PyzorError::from)
    }

    fn reorganize(&mut self, cleanup_age: i64) -> Result<()> {
        let cutoff = now_timestamp() - cleanup_age;
        self.records.retain(|_, record| {
            record
                .r_updated
                .map(|updated| updated >= cutoff)
                .unwrap_or(true)
        });
        self.sync()
    }
}
impl DigestDatabase for FileDatabase {
    fn get(&mut self, digest: &str) -> Result<Record> {
        Ok(FileDatabase::get(self, digest))
    }

    fn set(&mut self, digest: &str, record: Record) -> Result<()> {
        FileDatabase::set(self, digest, record)
    }

    fn report(&mut self, digests: &[String]) -> Result<()> {
        FileDatabase::report(self, digests)
    }

    fn whitelist(&mut self, digests: &[String]) -> Result<()> {
        FileDatabase::whitelist(self, digests)
    }
}

pub fn encode_record(record: &Record) -> String {
    format!(
        "1,{},{},{},{},{},{}",
        record.r_count,
        encode_time(record.r_entered),
        encode_time(record.r_updated),
        record.wl_count,
        encode_time(record.wl_entered),
        encode_time(record.wl_updated)
    )
}

pub fn decode_record(value: &str) -> Option<Record> {
    let parts: Vec<_> = value.split(',').collect();
    if parts.len() == 3 {
        // Kept because this is explicitly documented as intentionally retained Pyzor 1.1.2 behavior.
        return Some(Record {
            r_count: parts[0].parse().ok()?,
            r_entered: decode_time(parts[1]),
            r_updated: decode_time(parts[2]),
            ..Record::default()
        });
    }
    if parts.len() != 7 || parts[0] != "1" {
        return None;
    }
    Some(Record {
        r_count: parts[1].parse().ok()?,
        r_entered: decode_time(parts[2]),
        r_updated: decode_time(parts[3]),
        wl_count: parts[4].parse().ok()?,
        wl_entered: decode_time(parts[5]),
        wl_updated: decode_time(parts[6]),
    })
}

fn encode_time(value: Option<i64>) -> String {
    value
        .map(format_python_datetime)
        .unwrap_or_else(|| "None".to_string())
}

fn decode_time(value: &str) -> Option<i64> {
    if value == "None" || value == "0" || value.is_empty() {
        return None;
    }
    if let Ok(timestamp) = value.parse() {
        return Some(timestamp);
    }
    parse_python_datetime(value)
}

fn format_python_datetime(timestamp: i64) -> String {
    crate::local_time::format_timestamp(timestamp)
}

fn parse_python_datetime(value: &str) -> Option<i64> {
    crate::local_time::parse_datetime(value)
}

pub const REDIS_V1_NAMESPACE: &str = "pyzord.digest_v1";
// Kept because this is explicitly documented as intentionally retained Pyzor 1.1.2 behavior.
pub const REDIS_V0_NAMESPACE: &str = "pyzord.digest";

pub fn redis_v1_key(digest: &str) -> String {
    format!("{REDIS_V1_NAMESPACE}.{digest}")
}

pub fn redis_v1_encode_record(record: &Record) -> [(&'static str, String); 6] {
    [
        ("r_count", record.r_count.to_string()),
        ("r_entered", redis_v1_time(record.r_entered).to_string()),
        ("r_updated", redis_v1_time(record.r_updated).to_string()),
        ("wl_count", record.wl_count.to_string()),
        ("wl_entered", redis_v1_time(record.wl_entered).to_string()),
        ("wl_updated", redis_v1_time(record.wl_updated).to_string()),
    ]
}

pub fn redis_v1_decode_record<I, K, V>(fields: I) -> Record
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    let mut record = Record::default();
    for (key, value) in fields {
        match key.as_ref() {
            "r_count" => record.r_count = value.as_ref().parse().unwrap_or(0),
            "r_entered" => record.r_entered = decode_time(value.as_ref()),
            "r_updated" => record.r_updated = decode_time(value.as_ref()),
            "wl_count" => record.wl_count = value.as_ref().parse().unwrap_or(0),
            "wl_entered" => record.wl_entered = decode_time(value.as_ref()),
            "wl_updated" => record.wl_updated = decode_time(value.as_ref()),
            _ => {}
        }
    }
    record
}

pub fn redis_v0_key(digest: &str) -> String {
    format!("{REDIS_V0_NAMESPACE}.{digest}")
}

pub fn redis_v0_encode_record(record: &Record) -> String {
    format!(
        "{},{},{},{},{},{}",
        record.r_count,
        redis_v0_time(record.r_entered),
        redis_v0_time(record.r_updated),
        record.wl_count,
        redis_v0_time(record.wl_entered),
        redis_v0_time(record.wl_updated)
    )
}

pub fn redis_v0_decode_record(value: &str) -> Option<Record> {
    let fields: Vec<_> = value.split(',').collect();

    if fields.len() != 6 {
        return None;
    }
    Some(Record {
        r_count: fields[0].parse().ok()?,
        r_entered: redis_v0_decode_time(fields[1]),
        r_updated: redis_v0_decode_time(fields[2]),
        wl_count: fields[3].parse().ok()?,
        wl_entered: redis_v0_decode_time(fields[4]),
        wl_updated: redis_v0_decode_time(fields[5]),
    })
}

fn redis_v1_time(value: Option<i64>) -> i64 {
    value.unwrap_or(0)
}

fn redis_v0_time(value: Option<i64>) -> String {
    value.map(format_python_datetime).unwrap_or_default()
}

fn redis_v0_decode_time(value: &str) -> Option<i64> {
    if value.is_empty() {
        None
    } else {
        decode_time(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn record_round_trip_uses_python_gdbm_v1_format() {
        crate::local_time::with_timezone_for_tests("UTC", || {
            let record = Record {
                r_count: 24,
                wl_count: 42,
                r_entered: Some(1_400_221_786),
                r_updated: Some(1_400_221_794),
                wl_entered: None,
                wl_updated: None,
            };
            assert_eq!(
                encode_record(&record),
                "1,24,2014-05-16 06:29:46,2014-05-16 06:29:54,42,None,None"
            );
            assert_eq!(decode_record(&encode_record(&record)), Some(record));
        });
    }

    #[test]
    fn decodes_python_gdbm_v1_record_with_microseconds() {
        crate::local_time::with_timezone_for_tests("UTC", || {
            assert_eq!(
                decode_record("1,24,2014-05-16 06:29:46.123456,2014-05-16 06:29:54,42,None,None"),
                Some(Record {
                    r_count: 24,
                    wl_count: 42,
                    r_entered: Some(1_400_221_786),
                    r_updated: Some(1_400_221_794),
                    wl_entered: None,
                    wl_updated: None,
                })
            );
        });
    }

    #[test]
    fn decodes_legacy_three_field_record() {
        assert_eq!(
            decode_record("24,1400221786,1400221794"),
            Some(Record {
                r_count: 24,
                r_entered: Some(1_400_221_786),
                r_updated: Some(1_400_221_794),
                ..Record::default()
            })
        );
    }
    #[test]
    fn redis_v1_format_matches_reference_namespace_and_fields() {
        let digest = "7421216f915a87e02da034cc483f5c876e1a1338";
        let record = Record {
            r_count: 24,
            wl_count: 42,
            r_entered: Some(1_400_221_786),
            r_updated: Some(1_400_221_794),
            wl_entered: None,
            wl_updated: None,
        };
        assert_eq!(
            redis_v1_key(digest),
            "pyzord.digest_v1.7421216f915a87e02da034cc483f5c876e1a1338"
        );
        let encoded = redis_v1_encode_record(&record);
        assert!(encoded.contains(&("r_count", "24".to_string())));
        assert!(encoded.contains(&("r_entered", "1400221786".to_string())));
        assert!(encoded.contains(&("wl_entered", "0".to_string())));
        assert_eq!(redis_v1_decode_record(encoded), record);
    }

    #[test]
    fn redis_v0_format_matches_reference_namespace_and_record_string() {
        crate::local_time::with_timezone_for_tests("UTC", || {
            let digest = "7421216f915a87e02da034cc483f5c876e1a1338";
            let record = Record {
                r_count: 24,
                wl_count: 42,
                r_entered: Some(1_400_221_786),
                r_updated: Some(1_400_221_794),
                wl_entered: None,
                wl_updated: None,
            };
            assert_eq!(
                redis_v0_key(digest),
                "pyzord.digest.7421216f915a87e02da034cc483f5c876e1a1338"
            );
            assert_eq!(
                redis_v0_encode_record(&record),
                "24,2014-05-16 06:29:46,2014-05-16 06:29:54,42,,"
            );
            assert_eq!(
                redis_v0_decode_record(&redis_v0_encode_record(&record)),
                Some(record)
            );
        });
    }

    #[test]
    fn gdbm_and_redis_v0_datetime_strings_use_python_local_time() {
        crate::local_time::with_timezone_for_tests("Europe/Paris", || {
            let record = Record {
                r_count: 24,
                wl_count: 0,
                r_entered: Some(1_400_221_786),
                r_updated: Some(1_400_221_794),
                wl_entered: None,
                wl_updated: None,
            };

            assert_eq!(
                encode_record(&record),
                "1,24,2014-05-16 08:29:46,2014-05-16 08:29:54,0,None,None"
            );
            assert_eq!(decode_record(&encode_record(&record)), Some(record.clone()));
            assert_eq!(
                redis_v0_encode_record(&record),
                "24,2014-05-16 08:29:46,2014-05-16 08:29:54,0,,"
            );
            assert_eq!(
                redis_v0_decode_record(&redis_v0_encode_record(&record)),
                Some(record)
            );
        });
    }

    #[test]
    fn file_database_cleanup_age_removes_stale_gdbm_records_like_reference() {
        let path = temp_database_path("cleanup-stale");
        let now = now_timestamp();
        let stale = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let fresh = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        {
            let mut db = FileDatabase::open(&path).unwrap();
            db.set(
                stale,
                Record {
                    r_count: 24,
                    r_updated: Some(now - 3 * 86_400),
                    ..Record::default()
                },
            )
            .unwrap();
            db.set(
                fresh,
                Record {
                    r_count: 42,
                    r_updated: Some(now),
                    ..Record::default()
                },
            )
            .unwrap();
        }

        let db = FileDatabase::open_with_cleanup_age(&path, Some(86_400)).unwrap();
        assert_eq!(db.get(stale), Record::default());
        assert_eq!(db.get(fresh).r_count, 42);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn file_database_cleanup_age_zero_keeps_stale_gdbm_records_like_reference() {
        let path = temp_database_path("cleanup-zero-disabled");
        let digest = "dddddddddddddddddddddddddddddddddddddddd";

        {
            let mut db = FileDatabase::open(&path).unwrap();
            db.set(
                digest,
                Record {
                    r_count: 24,
                    r_updated: Some(now_timestamp() - 3 * 86_400),
                    ..Record::default()
                },
            )
            .unwrap();
        }

        let db = FileDatabase::open_with_cleanup_age(&path, Some(0)).unwrap();
        assert_eq!(db.get(digest).r_count, 24);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn file_database_without_cleanup_age_keeps_stale_gdbm_records_like_reference() {
        let path = temp_database_path("cleanup-disabled");
        let digest = "cccccccccccccccccccccccccccccccccccccccc";

        {
            let mut db = FileDatabase::open(&path).unwrap();
            db.set(
                digest,
                Record {
                    r_count: 24,
                    r_updated: Some(now_timestamp() - 3 * 86_400),
                    ..Record::default()
                },
            )
            .unwrap();
        }

        let db = FileDatabase::open_with_cleanup_age(&path, None).unwrap();
        assert_eq!(db.get(digest).r_count, 24);
        let _ = std::fs::remove_file(path);
    }

    fn temp_database_path(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "pyzor-engine-{name}-{}-{nanos}.db",
            std::process::id()
        ))
    }
}
