use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::local_time;

#[derive(Clone, Debug)]
pub struct Logger {
    file_path: Option<PathBuf>,
    debug: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Level {
    Debug = 10,
    Info = 20,
    Warning = 30,
    Error = 40,
    Critical = 50,
}

impl Level {
    fn label(self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warning => "WARNING",
            Self::Error => "ERROR",
            Self::Critical => "CRITICAL",
        }
    }
}

impl Logger {
    pub fn new(_name: &str, file_path: Option<String>, debug: bool) -> io::Result<Self> {
        let file_path = file_path.filter(|path| !path.is_empty()).map(PathBuf::from);
        if let Some(path) = &file_path {
            OpenOptions::new().create(true).append(true).open(path)?;
        }
        Ok(Self { file_path, debug })
    }

    pub fn debug(&self, message: impl AsRef<str>) {
        self.log(Level::Debug, message);
    }

    pub fn info(&self, message: impl AsRef<str>) {
        self.log(Level::Info, message);
    }

    pub fn warning(&self, message: impl AsRef<str>) {
        self.log(Level::Warning, message);
    }

    pub fn error(&self, message: impl AsRef<str>) {
        self.log(Level::Error, message);
    }

    pub fn critical(&self, message: impl AsRef<str>) {
        self.log(Level::Critical, message);
    }

    pub fn log(&self, level: Level, message: impl AsRef<str>) {
        let line = format!(
            "{} ({}) {} {}\n",
            timestamp(),
            std::process::id(),
            level.label(),
            message.as_ref()
        );

        if level >= self.stream_level() {
            eprint!("{line}");
        }
        if level >= self.file_level()
            && let Some(path) = &self.file_path
            && let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path)
        {
            let _ = file.write_all(line.as_bytes());
        }
    }

    fn stream_level(&self) -> Level {
        if self.debug {
            Level::Debug
        } else {
            Level::Critical
        }
    }

    fn file_level(&self) -> Level {
        if self.debug {
            Level::Debug
        } else {
            Level::Info
        }
    }
}

fn timestamp() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!(
        "{},{:03}",
        local_time::format_timestamp(duration.as_secs() as i64),
        duration.subsec_millis()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_logger_writes_critical_to_stderr_level_and_info_to_file_level() {
        let logger = Logger {
            file_path: None,
            debug: false,
        };
        assert_eq!(logger.stream_level(), Level::Critical);
        assert_eq!(logger.file_level(), Level::Info);
    }

    #[test]
    fn debug_logger_writes_debug_to_stream_and_file() {
        let logger = Logger {
            file_path: None,
            debug: true,
        };
        assert_eq!(logger.stream_level(), Level::Debug);
        assert_eq!(logger.file_level(), Level::Debug);
    }
}
