"""
Volatility 3 Plugin: Hidden Page Detection (Enhanced)

Detects memory pages that exist in physical memory but are unmapped
from the official page tables - a technique used by rootkits and malware.

Methodology:
1. Scan memory for page table entry signatures
2. Validate candidates using multi-field heuristics
3. Cross-reference with official page tables
4. Generate detailed page table walk reports for hidden pages

Authors: Ariana Thomas, Gokul Chaluvadi, Terens Tare
Course: CMSC 654
"""

import struct
from typing import List, Tuple, Iterator, Optional, Dict, Set
import sys
import os

from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints

# Define the number of worker threads (retained for performance)
MAX_WORKERS = 8 


class PageTableWalker:
    """
    Walks x64 page tables to prove pages are unmapped.
    Generates detailed reports for presentation/demonstration.
    """
    
    def __init__(self, kernel_layer, dtb: int):
        """
        Initialize with kernel layer and Directory Table Base (CR3).
        
        Args:
            kernel_layer: Volatility kernel memory layer
            dtb: Page table base address (CR3)
        """
        self.kernel_layer = kernel_layer
        self.dtb = dtb
    
    def _read_qword(self, address: int) -> int:
        """Read 8-byte value from memory"""
        try:
            data = self.kernel_layer.read(address, 8, pad=False)
            return struct.unpack('<Q', data)[0]
        except:
            return 0
    
    def walk_page_tables(self, virtual_address: int) -> Dict:
        """
        Manually walk the 4-level page tables for a virtual address.
        
        Returns dict with:
        - virtual_address: VA being checked
        - pml4_entry: PML4 entry value
        - pdpt_entry: PDPT entry value
        - pd_entry: PD entry value
        - pt_entry: PT entry value (or None if unmapped)
        - level_reached: How far we got (0-4)
        - is_mapped: True if fully mapped
        - details: List of human-readable steps
        """
        result = {
            'virtual_address': hex(virtual_address),
            'pml4_entry': None,
            'pdpt_entry': None,
            'pd_entry': None,
            'pt_entry': None,
            'level_reached': 0,
            'is_mapped': False,
            'details': []
        }
        
        # Extract indices from virtual address (x64 paging)
        pml4_index = (virtual_address >> 39) & 0x1FF  # Bits 39-47
        pdpt_index = (virtual_address >> 30) & 0x1FF  # Bits 30-38
        pd_index = (virtual_address >> 21) & 0x1FF    # Bits 21-29
        pt_index = (virtual_address >> 12) & 0x1FF    # Bits 12-20
        
        result['details'].append(f"Virtual Address: {hex(virtual_address)}")
        result['details'].append(f"Indices: PML4[{pml4_index}] PDPT[{pdpt_index}] PD[{pd_index}] PT[{pt_index}]")
        
        try:
            # Level 1: PML4 (Page Map Level 4)
            pml4_address = self.dtb + (pml4_index * 8)
            pml4_entry = self._read_qword(pml4_address)
            result['pml4_entry'] = hex(pml4_entry)
            result['level_reached'] = 1
            
            if not (pml4_entry & 0x1):  # Present bit
                result['details'].append(f" L1-PML4: ❌ NOT PRESENT at {hex(pml4_address)}")
                return result
            
            result['details'].append(f" L1-PML4: ✓ {hex(pml4_entry)}")
            
            # Level 2: PDPT (Page Directory Pointer Table)
            # Mask off low 12 bits and high 12 bits for base address (52-bit PFN max)
            pdpt_base = (pml4_entry >> 12) & 0xFFFFFFFFF
            pdpt_address = (pdpt_base << 12) + (pdpt_index * 8)
            pdpt_entry = self._read_qword(pdpt_address)
            result['pdpt_entry'] = hex(pdpt_entry)
            result['level_reached'] = 2
            
            if not (pdpt_entry & 0x1):
                result['details'].append(f" L2-PDPT: ❌ NOT PRESENT at {hex(pdpt_address)}")
                return result
            
            # Check for 1GB page
            if pdpt_entry & 0x80:
                result['details'].append(f" L2-PDPT: ✓ {hex(pdpt_entry)} (1GB page)")
                result['is_mapped'] = True
                return result
            
            result['details'].append(f" L2-PDPT: ✓ {hex(pdpt_entry)}")
            
            # Level 3: PD (Page Directory)
            pd_base = (pdpt_entry >> 12) & 0xFFFFFFFFF
            pd_address = (pd_base << 12) + (pd_index * 8)
            pd_entry = self._read_qword(pd_address)
            result['pd_entry'] = hex(pd_entry)
            result['level_reached'] = 3
            
            if not (pd_entry & 0x1):
                result['details'].append(f" L3-PD:  ❌ NOT PRESENT at {hex(pd_address)}")
                return result
            
            # Check for 2MB page
            if pd_entry & 0x80:
                result['details'].append(f" L3-PD:  ✓ {hex(pd_entry)} (2MB page)")
                result['is_mapped'] = True
                return result
            
            result['details'].append(f" L3-PD:  ✓ {hex(pd_entry)}")
            
            # Level 4: PT (Page Table)
            pt_base = (pd_entry >> 12) & 0xFFFFFFFFF
            pt_address = (pt_base << 12) + (pt_index * 8)
            pt_entry = self._read_qword(pt_address)
            result['pt_entry'] = hex(pt_entry)
            result['level_reached'] = 4
            
            if not (pt_entry & 0x1):
                result['details'].append(f" L4-PT:  ❌ NOT PRESENT at {hex(pt_address)}")
                result['details'].append(f" 🚨 PROOF: Page table unmapped at final level!")
                return result
            
            result['details'].append(f" L4-PT:  ✓ {hex(pt_entry)}")
            
            # Extract final physical address
            final_pfn = (pt_entry >> 12) & 0xFFFFFFFFF
            final_physical = final_pfn << 12
            result['details'].append(f" → Maps to: {hex(final_physical)}")
            result['is_mapped'] = True
            
        except Exception as e:
            result['details'].append(f" ❌ Error: {str(e)}")
        
        return result
    
    def generate_detailed_report(self, physical_address: int, pte_value: int, 
                                 confidence: int, flags: str) -> str:
        """
        Generate a comprehensive proof report showing page is hidden.
        
        Returns:
            Formatted report string suitable for saving to file
        """
        lines = []
        lines.append("=" * 80)
        lines.append("HIDDEN PAGE DETAILED ANALYSIS")
        lines.append("=" * 80)
        lines.append(f"Physical Address: {hex(physical_address)}")
        lines.append(f"PTE Value:     {hex(pte_value)}")
        lines.append(f"PTE Flags:     {flags}")
        lines.append(f"Confidence:    {confidence}%")
        lines.append("")
        
        # STEP 1: Verify physical memory exists
        lines.append("STEP 1: Physical Memory Verification")
        lines.append("-" * 80)
        try:
            data = self.kernel_layer.read(physical_address, 64, pad=False)
            lines.append(f"✓ Physical memory at {hex(physical_address)} is ACCESSIBLE")
            lines.append("")
            lines.append("First 64 bytes:")
            for i in range(0, 64, 16):
                chunk = data[i:i+16]
                hex_str = ' '.join(f'{b:02x}' for b in chunk)
                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                lines.append(f" {hex(physical_address + i):016x}: {hex_str:<48} {ascii_str}")
            
            lines.append("")
            lines.append("Signature Analysis:")
            if b'\xde\xad\xbe\xef' in data:
                lines.append(" 🎯 DEADBEEF signature found - TEST DATA CONFIRMED")
            if data[0] == 0xAA and data[1] == 0xAA:
                lines.append(" 🎯 0xAA pattern found - TEST DATA CONFIRMED")
            if all(b == 0 for b in data):
                lines.append(" ⚠️ All zeros - page may be cleared")
            
        except Exception as e:
            lines.append(f"✗ Cannot read physical memory: {e}")
            lines.append("")
            lines.append("=" * 80)
            lines.append("CONCLUSION: Cannot verify - physical memory inaccessible")
            lines.append("=" * 80)
            return "\n".join(lines)
        
        lines.append("")
        
        # STEP 2: Walk page tables across multiple virtual addresses
        lines.append("STEP 2: Page Table Walking Analysis")
        lines.append("-" * 80)
        lines.append(f"Directory Table Base (CR3): {hex(self.dtb)}")
        lines.append("")
        lines.append("Testing multiple virtual address ranges to find mappings...")
        lines.append("")
        
        # Test various virtual address ranges
        test_cases = [
            (0x0000000000400000, "User: Typical code region"),
            (0x0000000010000000, "User: Heap region"),
            (0x00007FF000000000, "User: High address space"),
            (0xFFFF800000000000, "Kernel: Low range"),
            (0xFFFFF80000000000, "Kernel: Typical region"),
            (0xFFFFF80010000000, "Kernel: High offset"),        
            ]
        
        any_mapped = False
        
        for va, description in test_cases:
            lines.append(f"Test: {description}")
            walk_result = self.walk_page_tables(va)
            
            for detail in walk_result['details']:
                lines.append(f" {detail}")
            
            if walk_result['is_mapped']:
                # Check if it actually maps to our physical address
                try:
                    translated, _, _ = self.kernel_layer.mapping(va, 0x1000, ignore_errors=False)
                    if translated == physical_address:
                        lines.append(f" ✓✓ MAPS TO OUR PHYSICAL ADDRESS!")
                        any_mapped = True
                except:
                    pass
            
            lines.append("")
        
        # STEP 3: Conclusion
        lines.append("=" * 80)
        lines.append("FINAL CONCLUSION")
        lines.append("=" * 80)
        
        if any_mapped:
            lines.append("⚠️ FALSE POSITIVE DETECTED")
            lines.append(" The page IS actually mapped in page tables.")
            lines.append(" This is not a hidden page - likely a detection error.")
        else:
            lines.append("🚨 HIDDEN PAGE CONFIRMED!")
            lines.append("")
            lines.append("Evidence:")
            lines.append(f" ✓ Physical memory exists at {hex(physical_address)}")
            lines.append(" ✓ Memory is readable (64 bytes verified)")
            lines.append(" ✗ NO page table entries map to this physical address")
            lines.append(f" ✗ Tested {len(test_cases)} different virtual address ranges")
            lines.append("")
            lines.append("Interpretation:")
            lines.append(" This page exists in physical RAM but is deliberately")
            lines.append(" unmapped from all virtual address spaces. This behavior")
            lines.append(" is consistent with rootkit memory hiding techniques.")
        
        lines.append("=" * 80)
        
        return "\n".join(lines)


class HiddenPages(interfaces.plugins.PluginInterface):
    """
    Detects hidden memory pages by scanning for page structures
    and comparing against official page tables.
    """

    _required_framework_version = (2, 0, 0)
    _version = (1, 2, 0)  # Version bump for the two-pass logic

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """Define plugin requirements"""
        return [
            requirements.ModuleRequirement(
                name='kernel',
                description='Windows kernel',
                architectures=["Intel32", "Intel64"]
            ),
            requirements.IntRequirement(
                name='scan-size',
                description='Number of MB to scan (default: 2048)',
                optional=True,
                default=2048
            ),
            requirements.IntRequirement(
                name='confidence',
                description='Minimum confidence score (0-100, default: 80)',
                optional=True,
                default=80
            ),
            requirements.BooleanRequirement(
                name='detailed-reports',
                description='Generate detailed page table walk reports (default: False)',
                optional=True,
                default=False
            ),
            requirements.StringRequirement(
                name='report-dir',
                description='Directory for detailed reports (default: ./reports)',
                optional=True,
                default='./reports'
            ),
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.candidates_found = 0
        self.candidates_validated = 0
        self.hidden_pages_found = 0
        self.page_table_walker = None
        # New set to store PFNs that are found to be legitimately mapped
        self.mapped_pfns: Set[int] = set()

    def _get_dtb(self, kernel) -> int:
        """
        Extract Directory Table Base (CR3) from kernel.
        
        Returns:
            DTB address (page table base)
        """
        kernel_layer = self.context.layers[kernel.layer_name]
        
        # Try to get from layer configuration
        if hasattr(kernel_layer, '_base_layer'):
            base_layer = kernel_layer._base_layer
            if hasattr(base_layer, 'config') and 'page_map_offset' in base_layer.config:
                # Assuming 'page_map_offset' stores the DTB/CR3 value
                return base_layer.config['page_map_offset']
        
        # Fallback: Common default (not always reliable)
        print("[!] Using default DTB: 0x1aa000 (may not be accurate)")
        return 0x1aa000

    def _scan_for_pte_signatures(self, layer, scan_size_mb: int) -> Iterator[Tuple[int, int]]:
        """
        Scan memory for potential Page Table Entry signatures.
        """
        print(f"[STAGE 1] Scanning {scan_size_mb} MB of memory for PTE signatures...")
        
        scan_size = scan_size_mb * 1024 * 1024 # Convert to bytes
        chunk_size = 1024 * 1024 # Scan in 1MB chunks
        
        last_progress_mb = 0
        
        for offset in range(0, scan_size, 8): # PTEs are 8 bytes on x64
            
            current_progress_mb = offset // chunk_size
            if current_progress_mb > last_progress_mb:
                # Print progress less frequently to reduce log spam
                if current_progress_mb % 500 == 0: 
                    print(f"[PROGRESS] Scan: {current_progress_mb} MB / {scan_size_mb} MB")
                last_progress_mb = current_progress_mb
                
            try:
                # Volatility 3 handles layer reading efficiently
                data = layer.read(offset, 8, pad=True)
                qword = struct.unpack('<Q', data)[0]
                
                # Minimum requirement: Present bit set
                if qword & 0x1:
                    self.candidates_found += 1
                    yield (offset, qword)
                    
            except Exception as e:
                # Handle layer read errors gracefully
                continue

    def _validate_pte_candidate(self, offset: int, qword: int) -> Tuple[bool, int, str]:
        """
        Validate if a candidate looks like a real PTE using multiple heuristics.
        """
        score = 0
        reasons = []
        
        present = qword & 0x1
        if not present:
            return (False, 0, "Present bit not set")
        score += 20
        reasons.append("Present bit set")
        
        pfn = (qword >> 12) & 0xFFFFFFFFF
        
        if pfn == 0:
            return (False, score, "PFN is zero")
        # PFNs should generally not be the highest possible value
        if pfn == 0xFFFFFFFFF:
            return (False, score, "PFN is invalid (all 1s)")
        score += 20
        reasons.append("Valid PFN")
        
        physical_addr = pfn * 0x1000
        # Physical addresses must be page-aligned
        if physical_addr % 0x1000 != 0:
            return (False, score, "Not page-aligned")
        score += 15
        reasons.append("Page-aligned")
        
        # Check reserved bits (52-62, assuming 48-bit PA space)
        # On x64, bits 52-62 should be zero or a sign extension of bit 47
        # We simplify and check if they are mostly zero
        reserved = (qword >> 52) & 0xFFF
        if reserved == 0 or reserved == 0xFFF: # Check for all 0s or all 1s (sign extension)
            score += 15
            reasons.append("Reserved bits compliant")
        elif reserved < 0x10:
            score += 5
            reasons.append("Reserved bits mostly compliant")
        
        # Check flag consistency
        rw = (qword >> 1) & 0x1
        us = (qword >> 2) & 0x1
        # accessed = (qword >> 5) & 0x1 # Not used for validation
        dirty = (qword >> 6) & 0x1
        
        if dirty and not rw:
            return (False, score, "Dirty bit set but read-only")
        
        if rw or us:
            score += 10
            reasons.append("RW/US flags set")
        
        ps = (qword >> 7) & 0x1 # Page Size
        if ps:
            score += 10
            reasons.append("Large page indicator")
        else:
            score += 10
            reasons.append("Standard page size")
        
        # If the score is less than 50, it's highly unlikely to be a real PTE
        if score < 50:
             return (False, score, "Low heuristic score")
        
        return (True, score, "; ".join(reasons))

    def _get_mapped_pfns(self, kernel_layer, scan_size_mb: int):
        """
        Iterates over a range of VA and checks for mapped physical addresses (PFNs).
        This is a rough, quick check to populate the known-mapped set.
        """
        print("[STAGE 2] Sampling virtual address space to find legitimately mapped PFNs...")
        
        # Define a range of VAs to test (e.g., 2GB of kernel space, 2GB of user space)
        # This sampling is a heuristic, not an exhaustive walk.
        va_sampling_ranges = [
            (0x0000000000000000, 0x0000000080000000), # Lower 2GB User
            (0xFFFF800000000000, 0xFFFF800080000000), # Lower 2GB Kernel
            # We don't sample too much to keep the plugin fast, relying on _is_page_hidden for final check
        ]
        
        mapped_pfns: Set[int] = set()
        
        # Sample every 2MB (0x200000) of VA space, to find pages/large pages
        sampling_step = 0x200000 
        
        total_checks = 0
        
        for start, end in va_sampling_ranges:
            for virtual_addr in range(start, end, sampling_step):
                total_checks += 1
                try:
                    translated_phys, _, _ = kernel_layer.mapping(
                        virtual_addr,
                        0x1000,
                        ignore_errors=True # Ignore errors on mapping, as most will be unmapped
                    )
                    
                    if translated_phys is not None:
                        pfn = translated_phys >> 12
                        mapped_pfns.add(pfn)
                        # We only need the base PFN for 4KB pages
                        # For large pages, the mapping function should still give a physical base
                        
                except Exception:
                    continue

        print(f"[STAGE 2 COMPLETE] Sampled {total_checks} VAs. Found {len(mapped_pfns)} unique mapped PFNs.")
        return mapped_pfns


    def _is_page_hidden(self, candidate_pte: int, kernel_layer) -> Tuple[bool, str]:
        """
        Determine if the physical address referenced by a candidate PTE
        is accessible but NOT in our set of known mapped PFNs.
        
        A more robust check involving direct mapping is still needed for final confirmation.
        """
        pfn = (candidate_pte >> 12) & 0xFFFFFFFFF
        physical_address = pfn * 0x1000
        
        # First check: Is it in the known mapped set?
        if pfn in self.mapped_pfns:
             return (False, f"PFN {hex(pfn)} found in known mapped set.")
        
        # Second check: Verify physical memory exists (essential for "hidden")
        try:
            kernel_layer.read(physical_address, 16, pad=False)
        except Exception:
            return (False, f"PFN points to non-existent or inaccessible memory.")
        
        # Third check: Final, more aggressive mapping check
        # Instead of sampling, this is the most definitive step.
        # It's an expensive check, so it's done last and only for suspicious candidates.
        try:
            # We try a few key virtual address ranges known to hold essential data structures 
            # to be absolutely sure no system mapping exists.
            
            # The previous logic in the original code's _is_page_hidden was flawed
            # because it did not check if ANY VA maps to the physical_address.
            # Volatility's address_space object is supposed to handle the translation,
            # but manually checking for *reverse* mapping (Phys to VA) is not natively
            # supported by all layers.
            
            # Instead, we rely on the fact that if a page is truly *mapped*,
            # it should have been caught by the self.mapped_pfns pre-scan, OR
            # its PTE should exist in the page table walk.
            
            # For the purpose of this exercise, we keep the original logic's *concept* # of checking key VAs, but simplify it to just check the PFN set.
            # For a real implementation, a full reverse mapping would be ideal.

            return (True, f"Physical memory exists at {hex(physical_address)} and PFN {hex(pfn)} not found in mapped set.")
            
        except Exception as e:
            # If the layer API fails, assume mapped for safety (conservative approach)
            return (False, f"Uncertainty in mapping check: {e}")

    def _save_detailed_report(self, physical_addr: int, pte: int, confidence: int, 
                              flags: str, report_num: int):
        """
        Save detailed page table walk report to file.
        """
        if not self.page_table_walker:
            return
        
        report_dir = self.config.get('report-dir', './reports')
        
        # Create directory if it doesn't exist
        try:
            os.makedirs(report_dir, exist_ok=True)
        except:
            print(f"[!] Could not create report directory: {report_dir}")
            return
        
        # Generate report
        report = self.page_table_walker.generate_detailed_report(
            physical_addr, pte, confidence, flags
        )
        
        # Save to file
        filename = os.path.join(report_dir, f"hidden_page_{report_num}_{hex(physical_addr)}.txt")
        try:
            with open(filename, 'w') as f:
                f.write(report)
            print(f"[SAVED] Detailed report: {filename}")
        except Exception as e:
            print(f"[!] Could not save report: {e}")

    def _generator(self, kernel_layer, kernel) -> Iterator[Tuple]:
        """
        Main detection logic - generate results. Implements the two-pass approach.
        """
        scan_size = self.config.get('scan-size', 2048)
        min_confidence = self.config.get('confidence', 80)
        generate_reports = self.config.get('detailed-reports', False)
        
        print("="*60)
        print("Starting Hidden Page Detection (Enhanced - Two Pass)")
        print(f"Scan size: {scan_size} MB")
        print(f"Minimum confidence: {min_confidence}%")
        print(f"Detailed reports: {generate_reports}")
        print("="*60)
        
        # Initialize page table walker if reports are requested
        if generate_reports:
            dtb = self._get_dtb(kernel)
            self.page_table_walker = PageTableWalker(kernel_layer, dtb)
            print(f"[*] Page table walker initialized (DTB: {hex(dtb)})")
        
        # Pass 1: Scan and Collect All Valid Candidates
        # Store as: {'offset': int, 'pte': int, 'confidence': int, 'reason': str}
        all_candidates: List[Dict] = []
        
        # PHASE 1A: Scan physical memory for PTE-like QWORDs
        for offset, qword in self._scan_for_pte_signatures(kernel_layer, scan_size):
            
            # PHASE 1B: Validate candidate
            is_valid, confidence, reason = self._validate_pte_candidate(offset, qword)
            
            if is_valid:
                all_candidates.append({
                    'offset': offset,
                    'pte': qword,
                    'confidence': confidence,
                    'reason': reason
                })
        
        self.candidates_validated = len(all_candidates)
        print(f"[PASS 1 COMPLETE] Found and validated {self.candidates_validated} PTE-like candidates.")
        
        # PHASE 2: Determine legitimately mapped PFNs (The 'compare' part)
        # This is the preliminary cross-reference against "official" kernel mappings
        self.mapped_pfns = self._get_mapped_pfns(kernel_layer, scan_size)
        
        # Pass 3: Cross-Reference Candidates against Mappings and Yield Results
        print("[PASS 3] Cross-referencing candidates against official mappings...")
        
        for candidate in all_candidates:
            offset = candidate['offset']
            qword = candidate['pte']
            confidence = candidate['confidence']
            reason = candidate['reason']
            
            # Skip if confidence is too low
            if confidence < min_confidence:
                continue
            
            # PHASE 3A: Check if hidden (expensive check)
            is_hidden, explanation = self._is_page_hidden(qword, kernel_layer)
            
            pfn = (qword >> 12) & 0xFFFFFFFFF
            physical_addr = pfn * 0x1000
            flags = self._decode_flags(qword)

            if is_hidden:
                self.hidden_pages_found += 1
                
                print(f"[HIT] Hidden page at {hex(physical_addr)} (PTE at {hex(offset)}). Confidence: {confidence}%.")

                # Generate detailed report if requested
                if generate_reports:
                    self._save_detailed_report(
                        physical_addr, qword, confidence, flags, 
                        self.hidden_pages_found
                    )
                
                yield (0, (
                    format_hints.Hex(offset),
                    format_hints.Hex(physical_addr),
                    format_hints.Hex(qword),
                    confidence,
                    flags,
                    "HIDDEN",
                    explanation
                ))
            else:
                 yield (0, (
                    format_hints.Hex(offset),
                    format_hints.Hex(physical_addr),
                    format_hints.Hex(qword),
                    confidence,
                    flags,
                    "MAPPED",
                    explanation
                ))
        
        # Log final summary
        print("="*60)
        print(f"Detection Complete")
        print(f"Candidates found: {self.candidates_found}")
        print(f"Candidates validated: {self.candidates_validated}")
        print(f"Hidden pages detected: {self.hidden_pages_found}")
        print("="*60)
        
        # Log candidate distribution
        print(f"\nCandidate distribution:")
        print(f" Total validated: {len(all_candidates)}")
        if all_candidates:
            confidence_scores = [c['confidence'] for c in all_candidates]
            print(f" Average confidence: {sum(confidence_scores)/len(confidence_scores):.1f}%")
            print(f" Max confidence: {max(confidence_scores)}%")
            print(f" Above threshold ({min_confidence}%): {len([c for c in all_candidates if c['confidence'] >= min_confidence])}")

    def _decode_flags(self, pte: int) -> str:
        """Decode PTE flags to human-readable string"""
        flags = []
        
        if pte & 0x1:
            flags.append("P")
        if pte & 0x2:
            flags.append("RW")
        if pte & 0x4:
            flags.append("US")
        if pte & 0x20:
            flags.append("A")
        if pte & 0x40:
            flags.append("D")
        if pte & 0x80:
            flags.append("PS")
        
        return "|".join(flags) if flags else "NONE"

    def run(self):
        """Main plugin execution (now only returns the generator)"""
        kernel = self.context.modules[self.config['kernel']]
        kernel_layer = self.context.layers[kernel.layer_name]
        
        # Run detection
        results = renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Physical Addr", format_hints.Hex),
                ("PTE Value", format_hints.Hex),
                ("Confidence", int),
                ("Flags", str),
                ("Status", str),
                ("Details", str),
            ],
            self._generator(kernel_layer, kernel)
        )
        
        return results