#![allow(unsafe_code)]

#[cfg(unix)]
use std::os::raw::{c_char, c_int, c_long};

#[cfg(unix)]
#[repr(C)]
struct Tm {
    tm_sec: c_int,
    tm_min: c_int,
    tm_hour: c_int,
    tm_mday: c_int,
    tm_mon: c_int,
    tm_year: c_int,
    tm_wday: c_int,
    tm_yday: c_int,
    tm_isdst: c_int,
    tm_gmtoff: c_long,
    tm_zone: *const c_char,
}

#[cfg(unix)]
type TimeT = c_long;

#[cfg(unix)]
unsafe extern "C" {
    fn localtime_r(timep: *const TimeT, result: *mut Tm) -> *mut Tm;
    fn mktime(timeptr: *mut Tm) -> TimeT;
    #[allow(dead_code)]
    fn tzset();
}

pub(crate) fn format_timestamp(timestamp: i64) -> String {
    if let Some((year, month, day, hour, minute, second)) = local_components(timestamp) {
        format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}")
    } else {
        let (year, month, day, hour, minute, second) = utc_components(timestamp);
        format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}")
    }
}

pub(crate) fn parse_datetime(value: &str) -> Option<i64> {
    let (date, time) = value.split_once(' ')?;
    let mut date = date.split('-');
    let year: i64 = date.next()?.parse().ok()?;
    let month: i64 = date.next()?.parse().ok()?;
    let day: i64 = date.next()?.parse().ok()?;
    if date.next().is_some() {
        return None;
    }

    let time = time.split_once('.').map(|(base, _)| base).unwrap_or(time);
    let mut time = time.split(':');
    let hour: i64 = time.next()?.parse().ok()?;
    let minute: i64 = time.next()?.parse().ok()?;
    let second: i64 = time.next()?.parse().ok()?;
    if time.next().is_some() {
        return None;
    }
    local_timestamp(year, month, day, hour, minute, second).or_else(|| {
        Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
    })
}

#[cfg(test)]
static TZ_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) fn with_timezone_for_tests<T>(timezone: &str, action: impl FnOnce() -> T) -> T {
    let _guard = TZ_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let previous = std::env::var_os("TZ");
    // SAFETY: tests serialize TZ mutation with TZ_TEST_LOCK before refreshing libc timezone state.
    unsafe {
        std::env::set_var("TZ", timezone);
    }
    refresh_timezone();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action));

    match previous {
        Some(value) => {
            // SAFETY: tests serialize TZ mutation with TZ_TEST_LOCK before refreshing libc timezone state.
            unsafe { std::env::set_var("TZ", value) }
        }
        None => {
            // SAFETY: tests serialize TZ mutation with TZ_TEST_LOCK before refreshing libc timezone state.
            unsafe { std::env::remove_var("TZ") }
        }
    }
    refresh_timezone();

    match result {
        Ok(value) => value,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

#[allow(dead_code)]
fn refresh_timezone() {
    #[cfg(unix)]
    {
        // SAFETY: tzset reads process environment and updates C library timezone state.
        unsafe {
            tzset();
        }
    }
}

#[cfg(unix)]
fn local_components(timestamp: i64) -> Option<(i64, i64, i64, i64, i64, i64)> {
    let time = timestamp as TimeT;
    let mut tm = std::mem::MaybeUninit::<Tm>::uninit();
    // SAFETY: localtime_r writes a valid tm into the provided out-pointer on success.
    let tm = unsafe {
        if localtime_r(&time, tm.as_mut_ptr()).is_null() {
            return None;
        }
        tm.assume_init()
    };
    Some((
        i64::from(tm.tm_year) + 1900,
        i64::from(tm.tm_mon) + 1,
        i64::from(tm.tm_mday),
        i64::from(tm.tm_hour),
        i64::from(tm.tm_min),
        i64::from(tm.tm_sec),
    ))
}

#[cfg(not(unix))]
fn local_components(_timestamp: i64) -> Option<(i64, i64, i64, i64, i64, i64)> {
    None
}

#[cfg(unix)]
fn local_timestamp(
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
) -> Option<i64> {
    let mut tm = Tm {
        tm_sec: second.try_into().ok()?,
        tm_min: minute.try_into().ok()?,
        tm_hour: hour.try_into().ok()?,
        tm_mday: day.try_into().ok()?,
        tm_mon: (month - 1).try_into().ok()?,
        tm_year: (year - 1900).try_into().ok()?,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: -1,
        tm_gmtoff: 0,
        tm_zone: std::ptr::null(),
    };
    // SAFETY: mktime normalizes a stack-allocated tm interpreted in the current local timezone.
    Some(unsafe { mktime(&mut tm) as i64 })
}

#[cfg(not(unix))]
fn local_timestamp(
    _year: i64,
    _month: i64,
    _day: i64,
    _hour: i64,
    _minute: i64,
    _second: i64,
) -> Option<i64> {
    None
}

fn utc_components(timestamp: i64) -> (i64, i64, i64, i64, i64, i64) {
    let days = timestamp.div_euclid(86_400);
    let seconds = timestamp.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds / 3600;
    let minute = (seconds % 3600) / 60;
    let second = seconds % 60;
    (year, month, day, hour, minute, second)
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * month_prime + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}
