use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::time::Duration;

use crate::Result;
use crate::account::now_timestamp;
use crate::engines::{
    DigestDatabase, Record, redis_v0_decode_record, redis_v0_encode_record, redis_v0_key,
    redis_v1_decode_record, redis_v1_encode_record, redis_v1_key,
};
use crate::error::PyzorError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedisDsn {
    pub host: String,
    pub port: u16,
    pub password: Option<String>,
    pub db: i64,
    pub username: Option<String>,
}

impl RedisDsn {
    pub fn parse(value: &str) -> Result<Self> {
        let mut fields = value.split(',');
        let host = fields.next().unwrap_or("");
        let port = fields.next().unwrap_or("");
        let password = fields.next().unwrap_or("");
        let db = fields.next().unwrap_or("");
        let username = fields.next().unwrap_or("");
        if !username.is_empty() && password.is_empty() {
            return Err(PyzorError::Comm(
                "Redis DSN username requires a password.".to_string(),
            ));
        }

        Ok(Self {
            host: if host.is_empty() {
                "localhost".to_string()
            } else {
                host.to_string()
            },
            port: if port.is_empty() {
                6379
            } else {
                port.parse()
                    .map_err(|_| PyzorError::Comm("Invalid Redis DSN port.".to_string()))?
            },
            password: if password.is_empty() {
                None
            } else {
                Some(password.to_string())
            },
            db: if db.is_empty() {
                0
            } else {
                db.parse()
                    .map_err(|_| PyzorError::Comm("Invalid Redis DSN database.".to_string()))?
            },
            username: if username.is_empty() {
                None
            } else {
                Some(username.to_string())
            },
        })
    }

    fn connect(&self) -> Result<RedisConnection> {
        let stream = if self.host.contains('/') {
            #[cfg(unix)]
            {
                RedisStream::Unix(UnixStream::connect(&self.host).map_err(redis_failure)?)
            }
            #[cfg(not(unix))]
            {
                return Err(PyzorError::Comm(
                    "Redis Unix socket DSNs are only supported on Unix.".to_string(),
                ));
            }
        } else {
            RedisStream::Tcp(
                TcpStream::connect((self.host.as_str(), self.port)).map_err(redis_failure)?,
            )
        };
        stream.set_timeouts(Duration::from_secs(5))?;
        let mut connection = RedisConnection {
            reader: BufReader::new(stream),
        };
        if let Some(password) = self.password.as_deref() {
            if let Some(username) = self.username.as_deref() {
                connection.command(&["AUTH", username, password])?;
            } else {
                connection.command(&["AUTH", password])?;
            }
        }
        let db = self.db.to_string();
        connection.command(&["SELECT", db.as_str()])?;
        Ok(connection)
    }
}

#[derive(Debug)]
pub struct RedisV1Database {
    dsn: RedisDsn,
    max_age: Option<i64>,
}

impl RedisV1Database {
    pub fn connect(dsn: impl AsRef<str>) -> Result<Self> {
        Self::connect_with_max_age(dsn, None)
    }

    pub fn connect_with_max_age(dsn: impl AsRef<str>, max_age: Option<i64>) -> Result<Self> {
        let db = Self {
            dsn: RedisDsn::parse(dsn.as_ref())?,
            max_age,
        };
        db.dsn.connect()?;
        Ok(db)
    }

    fn expire_if_needed(&self, connection: &mut RedisConnection, key: &str) -> Result<()> {
        if let Some(max_age) = self.max_age.filter(|age| *age != 0) {
            let max_age = max_age.to_string();
            connection.command(&["EXPIRE", key, max_age.as_str()])?;
        }
        Ok(())
    }
}

impl DigestDatabase for RedisV1Database {
    fn get(&mut self, digest: &str) -> Result<Record> {
        let mut connection = self.dsn.connect()?;
        let key = redis_v1_key(digest);
        let fields = decode_hgetall(connection.command(&["HGETALL", key.as_str()])?)?;
        Ok(redis_v1_decode_record(fields))
    }

    fn set(&mut self, digest: &str, record: Record) -> Result<()> {
        let mut connection = self.dsn.connect()?;
        let key = redis_v1_key(digest);
        let mut args = Vec::with_capacity(14);
        args.push(b"HSET".to_vec());
        args.push(key.as_bytes().to_vec());
        for (field, value) in redis_v1_encode_record(&record) {
            args.push(field.as_bytes().to_vec());
            args.push(value.into_bytes());
        }
        connection.command(&args)?;
        self.expire_if_needed(&mut connection, &key)
    }

    fn report(&mut self, digests: &[String]) -> Result<()> {
        let mut connection = self.dsn.connect()?;
        let now = now_timestamp().to_string();
        for digest in digests {
            let key = redis_v1_key(digest);
            connection.command(&["HINCRBY", key.as_str(), "r_count", "1"])?;
            connection.command(&["HSETNX", key.as_str(), "r_entered", now.as_str()])?;
            connection.command(&["HSET", key.as_str(), "r_updated", now.as_str()])?;
            self.expire_if_needed(&mut connection, &key)?;
        }
        Ok(())
    }

    fn whitelist(&mut self, digests: &[String]) -> Result<()> {
        let mut connection = self.dsn.connect()?;
        let now = now_timestamp().to_string();
        for digest in digests {
            let key = redis_v1_key(digest);
            connection.command(&["HINCRBY", key.as_str(), "wl_count", "1"])?;
            connection.command(&["HSETNX", key.as_str(), "wl_entered", now.as_str()])?;
            connection.command(&["HSET", key.as_str(), "wl_updated", now.as_str()])?;
            self.expire_if_needed(&mut connection, &key)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct RedisV0Database {
    dsn: RedisDsn,
    max_age: Option<i64>,
}
impl RedisV0Database {
    pub fn connect(dsn: impl AsRef<str>) -> Result<Self> {
        Self::connect_with_max_age(dsn, None)
    }

    pub fn connect_with_max_age(dsn: impl AsRef<str>, max_age: Option<i64>) -> Result<Self> {
        let db = Self {
            dsn: RedisDsn::parse(dsn.as_ref())?,
            max_age,
        };
        db.dsn.connect()?;
        Ok(db)
    }
}

impl DigestDatabase for RedisV0Database {
    fn get(&mut self, digest: &str) -> Result<Record> {
        let mut connection = self.dsn.connect()?;
        let key = redis_v0_key(digest);
        let value = bulk_string(connection.command(&["GET", key.as_str()])?)?;
        match value {
            Some(value) => redis_v0_decode_record(&value).ok_or_else(database_unavailable),
            None => Ok(Record::default()),
        }
    }

    fn set(&mut self, digest: &str, record: Record) -> Result<()> {
        let mut connection = self.dsn.connect()?;
        let key = redis_v0_key(digest);
        let value = redis_v0_encode_record(&record);
        if let Some(max_age) = self.max_age {
            let max_age = max_age.to_string();
            connection.command(&["SETEX", key.as_str(), max_age.as_str(), value.as_str()])?;
        } else {
            connection.command(&["SET", key.as_str(), value.as_str()])?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct RedisConnection {
    reader: BufReader<RedisStream>,
}

impl RedisConnection {
    fn command<S: AsRef<[u8]>>(&mut self, args: &[S]) -> Result<Resp> {
        write_command(self.reader.get_mut(), args).map_err(redis_failure)?;
        match read_resp(&mut self.reader).map_err(redis_failure)? {
            Resp::Error => Err(database_unavailable()),
            response => Ok(response),
        }
    }
}

#[derive(Debug)]
enum RedisStream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl RedisStream {
    fn set_timeouts(&self, timeout: Duration) -> Result<()> {
        match self {
            Self::Tcp(stream) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(redis_failure)?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(redis_failure)?;
            }
            #[cfg(unix)]
            Self::Unix(stream) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(redis_failure)?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(redis_failure)?;
            }
        }
        Ok(())
    }
}

impl Read for RedisStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buf),
            #[cfg(unix)]
            Self::Unix(stream) => stream.read(buf),
        }
    }
}

impl Write for RedisStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(buf),
            #[cfg(unix)]
            Self::Unix(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            #[cfg(unix)]
            Self::Unix(stream) => stream.flush(),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Resp {
    Simple,
    Error,
    Integer,
    Bulk(Option<Vec<u8>>),
    Array(Option<Vec<Resp>>),
}

fn write_command<S: AsRef<[u8]>>(writer: &mut RedisStream, args: &[S]) -> io::Result<()> {
    write!(writer, "*{}\r\n", args.len())?;
    for arg in args {
        let bytes = arg.as_ref();
        write!(writer, "${}\r\n", bytes.len())?;
        writer.write_all(bytes)?;
        writer.write_all(b"\r\n")?;
    }
    writer.flush()
}

fn read_resp<R: BufRead>(reader: &mut R) -> io::Result<Resp> {
    let mut prefix = [0u8; 1];
    reader.read_exact(&mut prefix)?;
    let line = read_line(reader)?;
    match prefix[0] {
        b'+' => Ok(Resp::Simple),
        b'-' => Ok(Resp::Error),
        b':' => {
            parse_i64(&line)?;
            Ok(Resp::Integer)
        }
        b'$' => {
            let len = parse_i64(&line)?;
            if len == -1 {
                return Ok(Resp::Bulk(None));
            }
            if len < 0 {
                return Err(invalid_data("invalid bulk length"));
            }
            let mut bytes = vec![0; len as usize];
            reader.read_exact(&mut bytes)?;
            read_crlf(reader)?;
            Ok(Resp::Bulk(Some(bytes)))
        }
        b'*' => {
            let len = parse_i64(&line)?;
            if len == -1 {
                return Ok(Resp::Array(None));
            }
            if len < 0 {
                return Err(invalid_data("invalid array length"));
            }
            let mut values = Vec::with_capacity(len as usize);
            for _ in 0..len {
                values.push(read_resp(reader)?);
            }
            Ok(Resp::Array(Some(values)))
        }
        _ => Err(invalid_data("unknown RESP prefix")),
    }
}

fn read_line<R: BufRead>(reader: &mut R) -> io::Result<String> {
    let mut bytes = Vec::new();
    if reader.read_until(b'\n', &mut bytes)? == 0 {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    }
    if bytes.ends_with(b"\r\n") {
        bytes.truncate(bytes.len() - 2);
    } else if bytes.ends_with(b"\n") {
        bytes.truncate(bytes.len() - 1);
    }
    String::from_utf8(bytes).map_err(|_| invalid_data("non-UTF8 RESP line"))
}

fn read_crlf<R: Read>(reader: &mut R) -> io::Result<()> {
    let mut crlf = [0u8; 2];
    reader.read_exact(&mut crlf)?;
    if crlf == *b"\r\n" {
        Ok(())
    } else {
        Err(invalid_data("missing RESP CRLF"))
    }
}

fn parse_i64(value: &str) -> io::Result<i64> {
    value
        .parse()
        .map_err(|_| invalid_data("invalid RESP integer"))
}

fn decode_hgetall(response: Resp) -> Result<HashMap<String, String>> {
    let values = match response {
        Resp::Array(Some(values)) => values,
        Resp::Array(None) => return Ok(HashMap::new()),
        _ => return Err(database_unavailable()),
    };
    if values.len() % 2 != 0 {
        return Err(database_unavailable());
    }
    let mut fields = HashMap::new();
    let mut values = values.into_iter();
    while let (Some(key), Some(value)) = (values.next(), values.next()) {
        let Some(key) = bulk_string(key)? else {
            return Err(database_unavailable());
        };
        let Some(value) = bulk_string(value)? else {
            return Err(database_unavailable());
        };
        fields.insert(key, value);
    }
    Ok(fields)
}

fn bulk_string(response: Resp) -> Result<Option<String>> {
    match response {
        Resp::Bulk(Some(bytes)) => String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| database_unavailable()),
        Resp::Bulk(None) => Ok(None),
        _ => Err(database_unavailable()),
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn redis_failure<T>(_error: T) -> PyzorError {
    database_unavailable()
}

fn database_unavailable() -> PyzorError {
    PyzorError::Comm("Database temporarily unavailable.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redis_dsn_defaults_match_python_engine() {
        assert_eq!(
            RedisDsn::parse("").unwrap(),
            RedisDsn {
                host: "localhost".to_string(),
                port: 6379,
                password: None,
                db: 0,
                username: None,
            }
        );
        assert_eq!(
            RedisDsn::parse("127.0.0.1,6380,secret,2").unwrap(),
            RedisDsn {
                host: "127.0.0.1".to_string(),
                port: 6380,
                password: Some("secret".to_string()),
                db: 2,
                username: None,
            }
        );
        assert_eq!(
            RedisDsn::parse("redis.example,6379,secret,0,ruzor").unwrap(),
            RedisDsn {
                host: "redis.example".to_string(),
                port: 6379,
                password: Some("secret".to_string()),
                db: 0,
                username: Some("ruzor".to_string()),
            }
        );
    }

    #[test]
    fn resp_parser_reads_bulk_and_arrays() {
        let mut reader = BufReader::new(&b"*2\r\n$7\r\nr_count\r\n$2\r\n24\r\n"[..]);
        let response = read_resp(&mut reader).unwrap();
        assert_eq!(
            response,
            Resp::Array(Some(vec![
                Resp::Bulk(Some(b"r_count".to_vec())),
                Resp::Bulk(Some(b"24".to_vec()))
            ]))
        );
    }
}
