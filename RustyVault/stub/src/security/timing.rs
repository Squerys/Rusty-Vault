use std::{env, fs::File, io::Read, process::exit};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::_rdtsc;

#[cfg(target_arch = "x86")]
use core::arch::x86::_rdtsc;


// ===============================
// WINDOWS IMPORTS
// ===============================

#[cfg(windows)]
use windows_sys::Win32::System::Performance::QueryPerformanceCounter;

#[cfg(windows)]
use windows_sys::Win32::System::SystemInformation::GetTickCount;


// ===============================
// LINUX IMPORTS
// ===============================

#[cfg(target_os = "linux")]
use libc::{clock_gettime, timespec, CLOCK_MONOTONIC, gettimeofday, timeval};


// ===============================
// CONFIG
// ===============================

#[inline(always)]
fn get_max_cycles() -> u64 { (5_000 * 10_000) ^ 0x0 } // 50_000_000

#[inline(always)]
fn get_max_highres() -> i64 { 10_000 * 1_000 } // 10_000_000

#[inline(always)] 
fn get_max_ms() -> u64 { 200 }


// ===============================
// LOW LEVEL TIMERS
// ===============================

#[inline]
pub unsafe fn get_time_cycles() -> u64 
{
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        _rdtsc()
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        0
    }
}


// ---------- HIGH RESOLUTION TIMER ----------

#[cfg(windows)]
fn highres_now() -> i64 
{
    let mut v: i64 = 0;
    unsafe { QueryPerformanceCounter(&mut v) };
    v
}

#[cfg(target_os = "linux")]
fn highres_now() -> i64 
{
    unsafe 
    {
        let mut ts: timespec = std::mem::zeroed();
        clock_gettime(CLOCK_MONOTONIC, &mut ts);
        ts.tv_sec as i64 * 1_000_000_000 + ts.tv_nsec as i64
    }
}


// ---------- MILLISECOND TIMER ----------

#[cfg(windows)]
fn millis_now() -> u64 
{
    unsafe { GetTickCount() as u64 }
}

#[cfg(target_os = "linux")]
fn millis_now() -> u64 
{
    unsafe 
    {
        let mut tv: timeval = std::mem::zeroed();
        gettimeofday(&mut tv, std::ptr::null_mut());
        tv.tv_sec as u64 * 1000 + (tv.tv_usec as u64 / 1000)
    }
}

// ===============================
// PAYLOAD DE TEST (ANTI-DEBUG)
// ===============================

#[inline(never)]
fn run_heavy_payload() -> u64
{
    let mut seed = 0x1337u64;
    for i in 0..10000 
    {
        seed = seed.wrapping_add(i).rotate_left(3) ^ 0x55AA55AA;
    }
    seed
}

// ===============================
// CHECK
// ===============================

pub fn timing_check() -> bool 
{
    let mut corrupted_mode = false;

    // -------- RDTSC CHECK --------
    let start_cycles = unsafe { get_time_cycles() };
    let _hash = run_heavy_payload(); 
    let end_cycles = unsafe { get_time_cycles() };

    if end_cycles > start_cycles && (end_cycles - start_cycles) > get_max_cycles() 
    {
        corrupted_mode = true;
    }

    // -------- HIGH RES TIMER CHECK --------
    let start_hr = highres_now();
    let _junk = run_heavy_payload(); 
    let end_hr = highres_now();

    if (end_hr - start_hr) > get_max_highres() 
    {
        corrupted_mode = true;
    }

    // -------- MILLISECOND TIMER CHECK --------
    let start_ms = millis_now();
    let _junk2 = run_heavy_payload();
    let delta = millis_now().saturating_sub(start_ms);

    if delta > get_max_ms() 
    {
        corrupted_mode = true;
    }

    corrupted_mode
}


pub fn check() -> bool 
{
    timing_check()
}
