#![allow(unsafe_code)]

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use gdbm_sys::{
    GDBM_FILE, GDBM_ITEM_NOT_FOUND, GDBM_REPLACE, GDBM_WRCREAT, datum, gdbm_close, gdbm_delete,
    gdbm_errno_location, gdbm_fetch, gdbm_firstkey, gdbm_nextkey, gdbm_open, gdbm_reorganize,
    gdbm_store, gdbm_strerror, gdbm_sync,
};
use libc::{c_void, free};

use crate::Result;
use crate::account::now_timestamp;
use crate::engines::{DigestDatabase, Record, decode_record, encode_record};
use crate::error::PyzorError;

#[derive(Debug)]
pub struct GdbmDatabase {
    db: RawGdbm,
}

impl GdbmDatabase {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_cleanup_age(path, None)
    }

    pub fn open_with_cleanup_age(path: impl AsRef<Path>, cleanup_age: Option<i64>) -> Result<Self> {
        let db = RawGdbm::open(path.as_ref())?;
        let mut database = Self { db };
        if let Some(cleanup_age) = cleanup_age.filter(|age| *age != 0) {
            database.reorganize(cleanup_age)?;
        }
        database.db.sync();
        Ok(database)
    }

    fn reorganize(&mut self, cleanup_age: i64) -> Result<()> {
        let cutoff = now_timestamp() - cleanup_age;
        for key in self.db.keys()? {
            let Some(value) = self.db.fetch(&key)? else {
                continue;
            };
            let value = std::str::from_utf8(&value).map_err(gdbm_failure)?;
            let Some(record) = decode_record(value) else {
                continue;
            };
            if record
                .r_updated
                .map(|updated| updated < cutoff)
                .unwrap_or(false)
            {
                self.db.delete(&key)?;
            }
        }
        self.db.reorganize()?;
        Ok(())
    }
}

impl DigestDatabase for GdbmDatabase {
    fn get(&mut self, digest: &str) -> Result<Record> {
        let Some(value) = self.db.fetch(digest.as_bytes())? else {
            return Ok(Record::default());
        };
        let value = std::str::from_utf8(&value).map_err(gdbm_failure)?;
        Ok(decode_record(value).unwrap_or_default())
    }

    fn set(&mut self, digest: &str, record: Record) -> Result<()> {
        self.db
            .store(digest.as_bytes(), encode_record(&record).as_bytes())?;
        self.db.sync();
        Ok(())
    }
}

#[derive(Debug)]
struct RawGdbm {
    handle: GDBM_FILE,
}

// The server serializes database access through a Mutex in threaded mode. The
// raw handle is never shared concurrently without that outer synchronization.
unsafe impl Send for RawGdbm {}

impl RawGdbm {
    fn open(path: &Path) -> Result<Self> {
        let path = CString::new(path.as_os_str().as_bytes()).map_err(gdbm_failure)?;
        let handle = unsafe {
            gdbm_open(
                path.as_ptr() as *mut c_char,
                0,
                GDBM_WRCREAT as c_int,
                0o666,
                None,
            )
        };
        if handle.is_null() {
            return Err(last_gdbm_error("gdbm_open failed"));
        }
        Ok(Self { handle })
    }

    fn fetch(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let key = datum_from_bytes("key", key)?;
        let value = unsafe { gdbm_fetch(self.handle, key) };
        if value.dptr.is_null() {
            return if last_gdbm_errno() == GDBM_ITEM_NOT_FOUND as c_int {
                Ok(None)
            } else {
                Err(last_gdbm_error("gdbm_fetch failed"))
            };
        }
        datum_into_vec(value).map(Some)
    }

    fn store(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let key = datum_from_bytes("key", key)?;
        let value = datum_from_bytes("value", value)?;
        let result = unsafe { gdbm_store(self.handle, key, value, GDBM_REPLACE as c_int) };
        if result < 0 {
            return Err(last_gdbm_error("gdbm_store failed"));
        }
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<()> {
        let key = datum_from_bytes("key", key)?;
        let result = unsafe { gdbm_delete(self.handle, key) };
        if result < 0 && last_gdbm_errno() != GDBM_ITEM_NOT_FOUND as c_int {
            return Err(last_gdbm_error("gdbm_delete failed"));
        }
        Ok(())
    }

    fn keys(&self) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        let mut key = unsafe { gdbm_firstkey(self.handle) };
        while !key.dptr.is_null() {
            let next = unsafe { gdbm_nextkey(self.handle, key) };
            out.push(datum_into_vec(key)?);
            key = next;
        }
        Ok(out)
    }

    fn reorganize(&mut self) -> Result<()> {
        let result = unsafe { gdbm_reorganize(self.handle) };
        if result < 0 {
            return Err(last_gdbm_error("gdbm_reorganize failed"));
        }
        Ok(())
    }

    fn sync(&self) {
        unsafe { gdbm_sync(self.handle) };
    }
}

impl Drop for RawGdbm {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { gdbm_close(self.handle) };
        }
    }
}

fn datum_from_bytes(what: &str, bytes: &[u8]) -> Result<datum> {
    if bytes.len() > c_int::MAX as usize {
        return Err(PyzorError::Comm(format!("gdbm {what} too large")));
    }
    Ok(datum {
        dptr: bytes.as_ptr() as *mut c_char,
        dsize: bytes.len() as c_int,
    })
}

fn datum_into_vec(value: datum) -> Result<Vec<u8>> {
    if value.dsize < 0 {
        unsafe { free(value.dptr as *mut c_void) };
        return Err(PyzorError::Comm("gdbm returned negative datum size".into()));
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(value.dptr as *const u8, value.dsize as usize) }
            .to_vec();
    unsafe { free(value.dptr as *mut c_void) };
    Ok(bytes)
}

fn last_gdbm_errno() -> c_int {
    unsafe { *gdbm_errno_location() }
}

fn last_gdbm_error(context: &str) -> PyzorError {
    let message = unsafe {
        let ptr = gdbm_strerror(last_gdbm_errno());
        if ptr.is_null() {
            "unknown gdbm error".to_string()
        } else {
            CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    };
    PyzorError::Comm(format!("{context}: {message}"))
}

fn gdbm_failure(error: impl std::fmt::Display) -> PyzorError {
    PyzorError::Comm(format!("gdbm error: {error}"))
}
