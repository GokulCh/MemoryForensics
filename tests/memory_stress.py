#!/usr/bin/env python3
"""
Memory Stress Test Script
Creates various memory allocations that may appear as hidden pages
when scanned by the Hidden Page Detection plugin.

Run this in the VM before capturing memory dump.
"""

import ctypes
import time
import sys
from ctypes import wintypes

# Windows API constants
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
MEM_DECOMMIT = 0x4000 # New constant for decommitting pages
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40

# Load Windows APIs
kernel32 = ctypes.windll.kernel32
VirtualAlloc = kernel32.VirtualAlloc
VirtualAlloc.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
VirtualAlloc.restype = wintypes.LPVOID

VirtualFree = kernel32.VirtualFree
VirtualFree.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]
VirtualFree.restype = wintypes.BOOL


class MemoryBlock:
    """Represents an allocated memory block"""
    
    def __init__(self, size, pattern_type):
        self.size = size
        self.address = None
        self.pattern_type = pattern_type
        # Used to hold the buffer in memory so it doesn't get GC'd prematurely
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
        
        print(f"[+] Allocated {self.size // 1024}KB at address: 0x{self.address:016x}")
        self.fill_pattern()
    
    def fill_pattern(self):
        """Fill memory with pattern"""
        # Create buffer
        buffer = (ctypes.c_ubyte * self.size)()
        
        if self.pattern_type == "pte_signature":
            # Write PTE-like structures every 4KB
            for offset in range(0, self.size, 4096):
                if offset + 8 <= self.size:
                    # Create fake PTE: Present + RW + Accessed + Dirty
                    # PFN is calculated to be unique and realistic
                    pfn = (offset // 4096) + 0x10000 
                    pte = (pfn << 12) | 0x63 # P=1, RW=1, A=1, D=1, User/Supervisor=1 
                    
                    # Write as 8-byte value (little-endian)
                    pte_bytes = pte.to_bytes(8, byteorder='little')
                    for i, byte in enumerate(pte_bytes):
                        buffer[offset + i] = byte
        
        elif self.pattern_type == "deadbeef":
            # Write 0xDEADBEEF signature
            signature = [0xEF, 0xBE, 0xAD, 0xDE]
            for offset in range(0, self.size, 4):
                if offset + 4 <= self.size:
                    for i, byte in enumerate(signature):
                        buffer[offset + i] = byte
        
        elif self.pattern_type == "zeros":
            # Already zeros
            pass
        
        elif self.pattern_type == "pattern_aa":
            # 0xAA pattern
            for i in range(self.size):
                buffer[i] = 0xAA
        
        # Write to allocated memory
        ctypes.memmove(self.address, buffer, self.size)
        print(f"    Pattern '{self.pattern_type}' written")
        
        # Keep the content alive in the Python process memory (optional, for safety)
        self.buffer_content = bytes(buffer) 

    def decommit(self):
        """Decommit memory block (remove VA mapping, leave physical memory)."""
        if self.address:
            # MEM_DECOMMIT removes the page table entries (PTEs) for the block.
            success = VirtualFree(self.address, self.size, MEM_DECOMMIT) 
            if success:
                print(f"[-] Decommitted memory at 0x{self.address:016x}. Pages are now unmapped.")
            else:
                raise Exception(f"Failed to decommit memory at 0x{self.address:016x}")
    
    def free(self):
        """Free memory block (final release)."""
        if self.address:
            VirtualFree(self.address, 0, MEM_RELEASE)
            print(f"[-] Released memory at 0x{self.address:016x}")
            self.address = None


def main():
    """Main execution"""
    print("=" * 70)
    print("Memory Stress Test for Hidden Page Detection")
    print("=" * 70)
    print()
    
    allocations = []
    
    try:
        # Allocation sequence
        scenarios = [
            (10 * 1024 * 1024, "pte_signature", "10MB with fake PTE signatures"),
            (5 * 1024 * 1024, "deadbeef", "5MB with DEADBEEF markers"),
            (20 * 1024 * 1024, "pattern_aa", "20MB with 0xAA pattern"),
            (15 * 1024 * 1024, "pte_signature", "15MB with more fake PTE signatures"),
        ]
        
        print("[*] Allocating memory blocks and writing patterns...\n")
        
        for i, (size, pattern, description) in enumerate(scenarios, 1):
            print(f"Block {i}: {description}")
            block = MemoryBlock(size, pattern)
            allocations.append(block)
            time.sleep(0.5)
            print()
            
        # NEW STEP: Decommit all allocated blocks
        print("\n[*] Decommitting memory blocks (removing official VA mappings)...\n")
        for i, block in enumerate(allocations, 1):
            block.decommit()
            time.sleep(0.5) # Wait briefly for OS to process

        
        total_mb = sum(b.size for b in allocations) / (1024 * 1024)
        
        print("=" * 70)
        print(f"[+] Allocation/Decommit complete: {len(allocations)} blocks ({total_mb:.1f} MB)")
        print("=" * 70)
        print()
        print("[!] IMPORTANT: DO NOT CLOSE THIS WINDOW!")
        print("[!] The process must remain alive for the memory to be released later.")
        print()
        print("Instructions:")
        print("  1. Leave this window open")
        print("  2. Capture memory dump from host (e.g., VBoxManage, vmss):")
        print("     VBoxManage debugvm \"YourVM\" dumpvmcore --filename test.elf")
        print("  3. Run Volatility 3 plugin: python3 vol.py -f test.elf windows.hiddenpages")
        print("  4. Press Ctrl+C to free memory and exit")
        print()
        
        # Keep process alive
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("\n\n[*] Interrupt received, cleaning up...")
    
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)
    
    finally:
        # Free all allocations
        print("\n[*] Freeing memory...")
        for block in allocations:
            # Freeing will ensure the reserved space is gone
            block.free() 
        print("\n[+] Cleanup complete. You can close this window.")


if __name__ == "__main__":
    if sys.platform != "win32":
        print("[!] This script requires Windows")
        sys.exit(1)
    
    print("[*] Note: Run as Administrator for best results\n")
    main()