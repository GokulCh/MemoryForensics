"""
Improved Memory Stress Test for Hidden Page Detection
Creates pages that will appear in physical memory but may not be
easily found through standard page table enumeration.
"""

import ctypes
import time
import sys
from ctypes import wintypes
import mmap

# Windows API constants
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40

# Load Windows APIs
kernel32 = ctypes.windll.kernel32
VirtualAlloc = kernel32.VirtualAlloc
VirtualAlloc.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
VirtualAlloc.restype = wintypes.LPVOID

VirtualFree = kernel32.VirtualFree
VirtualQuery = kernel32.VirtualQuery
VirtualQuery.argtypes = [wintypes.LPVOID, wintypes.LPVOID, ctypes.c_size_t]
VirtualQuery.restype = ctypes.c_size_t

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wintypes.LPVOID),
        ("AllocationBase", wintypes.LPVOID),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


class MemoryBlock:
    """Represents an allocated memory block with tracking"""
    
    def __init__(self, size, pattern_type, label):
        self.size = size
        self.address = None
        self.pattern_type = pattern_type
        self.label = label
        self.buffer_content = None
        self.allocate()
    
    def allocate(self):
        """Allocate memory block"""
        self.address = VirtualAlloc(
            None,
            self.size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        )
        
        if not self.address:
            raise Exception(f"Failed to allocate {self.size} bytes")
        
        print(f"[+] Allocated {self.size // 1024}KB at VA: 0x{self.address:016x}")
        
        # Query to get physical info
        mbi = MEMORY_BASIC_INFORMATION()
        result = VirtualQuery(self.address, ctypes.byref(mbi), ctypes.sizeof(mbi))
        if result:
            print(f"    Region size: {mbi.RegionSize}, State: 0x{mbi.State:x}, Type: 0x{mbi.Type:x}")
        
        self.fill_pattern()
    
    def fill_pattern(self):
        """Fill memory with distinctive patterns"""
        buffer = (ctypes.c_ubyte * self.size)()
        
        if self.pattern_type == "signature":
            # Write a clear signature at the start
            signature = b"HIDDEN_PAGE_TEST_MARKER_2024"
            for i, byte in enumerate(signature):
                if i < self.size:
                    buffer[i] = byte
            
            # Fill rest with pattern
            for offset in range(len(signature), self.size, 8):
                if offset + 8 <= self.size:
                    # Write offset value (makes each page unique)
                    value = offset.to_bytes(8, byteorder='little')
                    for i, byte in enumerate(value):
                        buffer[offset + i] = byte
        
        elif self.pattern_type == "deadbeef":
            signature = [0xEF, 0xBE, 0xAD, 0xDE]
            for offset in range(0, self.size, 4):
                if offset + 4 <= self.size:
                    for i, byte in enumerate(signature):
                        buffer[offset + i] = byte
        
        elif self.pattern_type == "repeated":
            # Repeating pattern with virtual address embedded
            marker = f"BLOCK_{self.label}_VA_0x{self.address:016x}_".encode()
            for offset in range(0, self.size, len(marker)):
                for i, byte in enumerate(marker):
                    if offset + i < self.size:
                        buffer[offset + i] = byte
        
        # Write to allocated memory
        ctypes.memmove(self.address, buffer, self.size)
        print(f"    Pattern '{self.pattern_type}' written")
        
        # Force pages to be committed to physical memory
        # Read back to ensure pages are in RAM
        dummy = ctypes.c_ubyte.from_address(self.address).value
        dummy = ctypes.c_ubyte.from_address(self.address + self.size - 1).value
        
        self.buffer_content = bytes(buffer)
    
    def get_info(self):
        """Return allocation info"""
        return {
            'label': self.label,
            'virtual_address': self.address,
            'size': self.size,
            'pattern': self.pattern_type
        }
    
    def free(self):
        """Free memory block"""
        if self.address:
            VirtualFree(self.address, 0, MEM_RELEASE)
            print(f"[-] Released memory at 0x{self.address:016x}")
            self.address = None


def main():
    """Main execution"""
    print("=" * 70)
    print("Memory Stress Test for Hidden Page Detection v2")
    print("=" * 70)
    print()
    
    allocations = []
    allocation_map = []
    
    try:
        # Create multiple allocations with distinctive patterns
        scenarios = [
            (4 * 1024 * 1024, "signature", "A"),
            (4 * 1024 * 1024, "deadbeef", "B"),
            (8 * 1024 * 1024, "repeated", "C"),
            (4 * 1024 * 1024, "signature", "D"),
        ]
        
        print("[*] Allocating memory blocks with distinctive patterns...\n")
        
        for i, (size, pattern, label) in enumerate(scenarios, 1):
            print(f"Block {label}: {size // (1024*1024)}MB, pattern='{pattern}'")
            block = MemoryBlock(size, pattern, label)
            allocations.append(block)
            allocation_map.append(block.get_info())
            time.sleep(0.2)
            print()
        
        total_mb = sum(b.size for b in allocations) / (1024 * 1024)
        
        print("=" * 70)
        print(f"[+] Allocation complete: {len(allocations)} blocks ({total_mb:.1f} MB)")
        print("=" * 70)
        print()
        
        # Print allocation map
        print("ALLOCATION MAP (for reference):")
        print("-" * 70)
        for info in allocation_map:
            print(f"  Block {info['label']}: VA=0x{info['virtual_address']:016x}, "
                  f"Size={info['size']//1024}KB, Pattern={info['pattern']}")
        print("-" * 70)
        print()
        
        print("[!] IMPORTANT: Keep this window open!")
        print()
        print("Instructions:")
        print("  1. Leave this process running")
        print("  2. Capture memory dump:")
        print("     - VirtualBox: VBoxManage debugvm 'VMName' dumpvmcore --filename dump.elf")
        print("     - VMware: Suspend VM and use .vmem file")
        print("  3. Run detection plugin:")
        print("     python3 vol.py -f dump.elf windows.hiddenpages --scan-size 512")
        print("  4. Search for signatures in dump:")
        print("     strings dump.elf | grep 'HIDDEN_PAGE_TEST_MARKER'")
        print("  5. Press Ctrl+C here when done")
        print()
        
        # Keep process alive
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("\n\n[*] Interrupt received, cleaning up...")
    
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    finally:
        print("\n[*] Freeing memory...")
        for block in allocations:
            block.free()
        print("\n[+] Cleanup complete.")


if __name__ == "__main__":
    if sys.platform != "win32":
        print("[!] This script requires Windows")
        sys.exit(1)
    
    print("[*] Note: Run as Administrator for best results\n")
    main()