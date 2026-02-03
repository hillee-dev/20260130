use std::ptr;
use winapi::ctypes::c_void;

use winapi::shared::basetsd::SIZE_T;
use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::um::{
    errhandlingapi::GetLastError,
    memoryapi::VirtualQueryEx,
    psapi::GetProcessMemoryInfo,
    winnt::{MEM_FREE, MEMORY_BASIC_INFORMATION, PAGE_NOACCESS},
};

// 导入进程模块的常量（INVALID_HANDLE_VALUE）
use crate::process::handle::INVALID_HANDLE_VALUE;

// 定义必需的DLL大小常量（加pub，外部可访问）
pub const REQUIRED_DLL_SIZE: SIZE_T = 1024 * 1024; // 1MB

/// 封装：查询进程的整体内存使用情况（加pub）
pub fn query_process_overall_memory(h_process: *mut c_void) -> Result<(), &'static str> {
    let mut mem_info = winapi::um::psapi::PROCESS_MEMORY_COUNTERS_EX {
        cb: std::mem::size_of::<winapi::um::psapi::PROCESS_MEMORY_COUNTERS_EX>() as DWORD,
        PageFaultCount: 0,
        PeakWorkingSetSize: 0,
        WorkingSetSize: 0,
        QuotaPeakPagedPoolUsage: 0,
        QuotaPagedPoolUsage: 0,
        QuotaPeakNonPagedPoolUsage: 0,
        QuotaNonPagedPoolUsage: 0,
        PagefileUsage: 0,
        PeakPagefileUsage: 0,
        PrivateUsage: 0,
    };

    unsafe {
        if GetProcessMemoryInfo(
            h_process,
            &mut mem_info as *mut _ as *mut winapi::um::psapi::PROCESS_MEMORY_COUNTERS,
            mem_info.cb,
        ) == 0
        {
            return Err("获取进程整体内存信息失败");
        }
    }

    println!("=== 目标进程整体内存使用情况 ===");
    println!(
        "工作集大小（物理内存使用）：{:.2} MB",
        mem_info.WorkingSetSize as f64 / 1024.0 / 1024.0
    );
    println!(
        "页面文件使用（虚拟内存使用）：{:.2} MB",
        mem_info.PagefileUsage as f64 / 1024.0 / 1024.0
    );
    println!(
        "私有内存大小：{:.2} MB",
        mem_info.PrivateUsage as f64 / 1024.0 / 1024.0
    );
    println!("====================================\n");

    Ok(())
}

/// 封装：枚举目标进程的虚拟地址空间（加pub）
pub fn check_process_virtual_address_space(h_process: *mut c_void) -> Result<bool, &'static str> {
    let mut address: LPVOID = 0 as LPVOID;
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>() as SIZE_T;

    println!(
        "=== 枚举目标进程虚拟地址空间（查找 {} MB 连续空闲区域）===",
        REQUIRED_DLL_SIZE as f64 / 1024.0 / 1024.0
    );

    unsafe {
        while VirtualQueryEx(h_process, address, &mut mbi, mbi_size) == mbi_size {
            if mbi.State == MEM_FREE && mbi.Protect == PAGE_NOACCESS {
                let region_size = mbi.RegionSize;
                let region_start = mbi.BaseAddress as u64;
                let region_end = region_start + region_size as u64;

                println!(
                    "空闲区域：0x{:X} - 0x{:X}，大小：{:.2} MB",
                    region_start,
                    region_end,
                    region_size as f64 / 1024.0 / 1024.0
                );

                if region_size >= REQUIRED_DLL_SIZE {
                    println!("\n找到足够大的空闲虚拟地址区域！大小满足DLL加载要求。");
                    return Ok(true);
                }
            }
            address = ((mbi.BaseAddress as u64) + mbi.RegionSize as u64) as LPVOID;
        }
    }

    Err("未找到足够大的虚拟地址空闲区域，无法加载DLL")
}