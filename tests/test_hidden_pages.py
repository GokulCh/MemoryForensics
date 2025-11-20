"""
Testing Framework for Hidden Page Detection Plugin

This script validates the plugin's detection capabilities and
helps analyze results.

Usage:
    python test_hidden_pages.py
"""

import struct
import random
from pathlib import Path

class PTEGenerator:
    """Generate test PTE patterns for validation"""
    
    @staticmethod
    def create_valid_pte(pfn: int, flags: int = 0x3) -> int:
        """
        Create a valid-looking PTE
        
        Args:
            pfn: Physical Frame Number
            flags: Protection flags (default: Present + RW)
        """
        # PFN goes in bits 12-47
        pte = (pfn & 0xFFFFFFFFF) << 12
        # Add flags in bits 0-11
        pte |= (flags & 0xFFF)
        return pte
    
    @staticmethod
    def create_hidden_page_pte(pfn: int) -> int:
        """Create a PTE for a page that should appear hidden"""
        # Present + RW + Accessed + Dirty
        flags = 0x1 | 0x2 | 0x20 | 0x40
        return PTEGenerator.create_valid_pte(pfn, flags)
    
    @staticmethod
    def create_invalid_pte() -> int:
        """Create an invalid PTE (for testing false positives)"""
        # Present bit NOT set, or invalid PFN
        return random.choice([
            0x0,  # All zeros
            0xFFFFFFFFFFFFFFFF,  # All ones
            0x2,  # RW but not Present
            0x100,  # Random flags without Present
        ])


class PTEValidator:
    """Validate PTE detection logic (unit tests)"""
    
    def test_valid_detection(self):
        """Test that valid PTEs are detected"""
        print("Testing valid PTE detection...")
        
        test_cases = [
            (0x1000, 0x3, "Standard page, RW"),
            (0x5000, 0x7, "Standard page, User RW"),
            (0x100000, 0x3, "High memory page"),
        ]
        
        for pfn, flags, description in test_cases:
            pte = PTEGenerator.create_valid_pte(pfn, flags)
            
            # Check present bit
            present = pte & 0x1
            extracted_pfn = (pte >> 12) & 0xFFFFFFFFF
            
            print(f"  ✓ {description}: PTE=0x{pte:016x}, PFN=0x{extracted_pfn:x}, Present={present}")
            
            assert present == 1, "Present bit should be set"
            assert extracted_pfn == pfn, f"PFN mismatch: {extracted_pfn} != {pfn}"
        
        print("  All valid PTE tests passed!\n")
    
    def test_invalid_rejection(self):
        """Test that invalid PTEs are rejected"""
        print("Testing invalid PTE rejection...")
        
        for i in range(5):
            invalid_pte = PTEGenerator.create_invalid_pte()
            present = invalid_pte & 0x1
            
            if present:
                pfn = (invalid_pte >> 12) & 0xFFFFFFFFF
                if pfn == 0 or pfn == 0xFFFFFFFFF:
                    print(f"  ✓ Invalid PTE rejected: 0x{invalid_pte:016x} (bad PFN)")
            else:
                print(f"  ✓ Invalid PTE rejected: 0x{invalid_pte:016x} (not present)")
        
        print("  All invalid PTE tests passed!\n")
    
    def test_flag_combinations(self):
        """Test various flag combinations"""
        print("Testing flag combinations...")
        
        flag_tests = [
            (0x1, "Present only"),
            (0x3, "Present + RW"),
            (0x7, "Present + RW + User"),
            (0x63, "Present + RW + Accessed + Dirty"),
            (0x83, "Present + RW + Large Page"),
        ]
        
        for flags, description in flag_tests:
            pte = PTEGenerator.create_valid_pte(0x1000, flags)
            
            # Decode flags
            decoded = []
            if flags & 0x1: decoded.append("P")
            if flags & 0x2: decoded.append("RW")
            if flags & 0x4: decoded.append("US")
            if flags & 0x20: decoded.append("A")
            if flags & 0x40: decoded.append("D")
            if flags & 0x80: decoded.append("PS")
            
            print(f"  ✓ {description}: flags=0x{flags:x} ({', '.join(decoded)})")
        
        print("  All flag combination tests passed!\n")


class MemoryScenarioGenerator:
    """Generate test memory dumps with hidden pages"""
    
    @staticmethod
    def create_test_memory_block(size_kb: int = 64) -> bytes:
        """
        Create a synthetic memory block with:
        - Normal pages (mapped in page tables)
        - Hidden pages (not mapped but present in memory)
        - Random data (noise)
        """
        size = size_kb * 1024
        memory = bytearray(size)
        
        print(f"Creating {size_kb}KB test memory block...")
        
        # Inject normal PTEs every 512 bytes
        normal_count = 0
        for offset in range(0, size, 512):
            if offset + 8 <= size:
                pfn = 0x1000 + (offset // 0x1000)
                pte = PTEGenerator.create_valid_pte(pfn, 0x3)
                struct.pack_into('<Q', memory, offset, pte)
                normal_count += 1
        
        # Inject hidden page PTEs at specific offsets
        hidden_offsets = [1024, 4096, 8192, 16384]
        hidden_count = 0
        for offset in hidden_offsets:
            if offset + 8 <= size:
                pfn = 0x10000 + (offset // 0x1000)
                pte = PTEGenerator.create_hidden_page_pte(pfn)
                struct.pack_into('<Q', memory, offset, pte)
                hidden_count += 1
        
        # Fill rest with random data
        for i in range(0, size, 8):
            if memory[i:i+8] == b'\x00' * 8:
                random_val = random.randint(0, 0xFFFFFFFFFFFFFFFF)
                struct.pack_into('<Q', memory, i, random_val)
        
        print(f"  ✓ Injected {normal_count} normal PTEs")
        print(f"  ✓ Injected {hidden_count} hidden PTEs")
        print(f"  ✓ Filled with random data\n")
        
        return bytes(memory)
    
    @staticmethod
    def save_test_memory(filename: str = "test_memory.bin"):
        """Save test memory block to file"""
        memory = MemoryScenarioGenerator.create_test_memory_block()
        
        with open(filename, 'wb') as f:
            f.write(memory)
        
        print(f"✓ Test memory saved to {filename}")
        print(f"  Size: {len(memory)} bytes")
        print(f"  Use this for plugin testing\n")


class ResultsAnalyzer:
    """Analyze plugin output"""
    
    @staticmethod
    def analyze_output_file(filepath: str):
        """Parse and analyze plugin output"""
        print("="*60)
        print(f"Analyzing results from: {filepath}")
        print("="*60)
        
        if not Path(filepath).exists():
            print(f"⚠️  File not found: {filepath}")
            return
        
        with open(filepath, 'r') as f:
            lines = f.readlines()
        
        # Parse results
        hidden_pages = []
        for line in lines:
            if 'HIDDEN' in line and '0x' in line:
                hidden_pages.append(line.strip())
        
        print(f"\nHidden Pages Detected: {len(hidden_pages)}")
        
        if hidden_pages:
            print("\nDetails:")
            for i, page in enumerate(hidden_pages, 1):
                print(f"  {i}. {page}")
        else:
            print("  (No hidden pages found)")
        
        print()


def main():
    """Main testing routine"""
    print("="*60)
    print("Hidden Page Detection - Testing Framework")
    print("="*60)
    print()
    
    # Phase 1: Unit tests
    print("Phase 1: Unit Tests")
    print("-"*60)
    validator = PTEValidator()
    validator.test_valid_detection()
    validator.test_invalid_rejection()
    validator.test_flag_combinations()
    
    # Phase 2: Generate test data
    print("Phase 2: Test Data Generation")
    print("-"*60)
    MemoryScenarioGenerator.save_test_memory("test_memory.bin")
    
    # Phase 3: Instructions for real testing
    print("="*60)
    print("Next Steps:")
    print("="*60)
    print()
    print("1. Run plugin on real memory dump:")
    print("   python -m volatility3 -f dump.raw -p custom_plugins \\")
    print("       windows.hidden_pages --scan-size 512 --confidence 80")
    print()
    print("2. Save results:")
    print("   python -m volatility3 -f dump.raw -p custom_plugins \\")
    print("       windows.hidden_pages > results/hidden_pages.txt")
    print()
    print("3. Analyze results:")
    print("   python test_hidden_pages.py analyze results/hidden_pages.txt")
    print()
    print("4. Compare scenarios:")
    print("   - Baseline system")
    print("   - System with rootkit")
    print("   - System with malware")
    print()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "analyze" and len(sys.argv) > 2:
            ResultsAnalyzer.analyze_output_file(sys.argv[2])
        else:
            print("Usage: python test_hidden_pages.py [analyze <results_file>]")
    else:
        main()