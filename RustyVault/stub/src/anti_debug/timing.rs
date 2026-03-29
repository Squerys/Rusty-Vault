use std::{env, fs::File, io::Read, process::exit};
use std::hint::black_box;

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
fn get_dynamic_threshold(base: u64, factor: u64) -> u64 {
    let x = black_box(base);
    x.wrapping_mul(factor) 
}

#[inline(always)]
fn get_secret_factor() -> u64 {
    let a = std::hint::black_box(10);
    let b = std::hint::black_box(10);
    a * b // Retourne 100, mais l'attaquant voit une multiplication de variables
}

fn get_max_cycles() -> u64 {
    let base = 500_000;
    get_secret_factor().wrapping_mul(base)
}

fn get_max_highres() -> i64 {
    get_dynamic_threshold(100_000, 100) as i64 // Résultat : 10 000 000
}

fn get_max_ms() -> u64 {
    get_dynamic_threshold(10, 5) // Résultat : 50 ms possible de monter a 100ms
}

// ===============================
// LOW LEVEL TIMERS
// ===============================

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub unsafe fn get_time_cycles() -> u64 
{
    unsafe 
    {
        #[cfg(target_arch = "x86_64")]
        return core::arch::x86_64::_rdtsc();

        #[cfg(target_arch = "x86")]
        return core::arch::x86::_rdtsc();
    }
}
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn get_time_cycles() -> u64 { 0 }

// ---------- HIGH RESOLUTION TIMER ----------

#[cfg(windows)]
fn highres_now() -> i64 
{
    unsafe{
        let mut v: i64 = 0;
        QueryPerformanceCounter(&mut v) ;
        v
    }
}

#[cfg(target_os = "linux")]
fn highres_now() -> i64 
{
    unsafe 
    {
        let mut ts: timespec = std::mem::zeroed();
        clock_gettime(CLOCK_MONOTONIC, &mut ts);
        (ts.tv_sec as i64 * 1_000_000_000) + ts.tv_nsec as i64
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
        let mut ts: timespec = std::mem::zeroed();
        clock_gettime(CLOCK_MONOTONIC, &mut ts);
        (ts.tv_sec as u64 * 1000) + (ts.tv_nsec as u64 / 1_000_000)
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
        seed = std::hint::black_box(seed.wrapping_add(i).rotate_left(3) ^ 0x55AA55AA);
    }
    black_box(seed)
}

// ===============================
// CHECK
// ===============================

pub fn timing_check() -> bool 
{
    let mut corrupted_mode = false;

    // -------- RDTSC CHECK --------
    let start_cycles = unsafe {get_time_cycles()} ;
    run_heavy_payload(); 
    let end_cycles = unsafe {get_time_cycles()};

    if end_cycles > start_cycles && (end_cycles - start_cycles) > get_max_cycles() 
    {
        corrupted_mode = true;
    }

    // -------- HIGH RES TIMER CHECK --------
    let start_hr = highres_now();
    run_heavy_payload(); 
    let end_hr = highres_now();

    if (end_hr - start_hr) > get_max_highres() 
    {
        corrupted_mode = true;
    }

    // -------- MILLISECOND TIMER CHECK --------
    let start_m = millis_now();
    run_heavy_payload();
    let end_m = millis_now();

    if end_m.saturating_sub(start_m) > get_max_ms() 
    {
        corrupted_mode = true;
    }

    corrupted_mode
}


pub fn check() -> bool 
{
    timing_check()
}
