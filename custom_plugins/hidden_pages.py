"""
Volatility 3 Plugin: Hidden Page Detection

Detects memory pages that exist in physical memory but are unmapped
from the official page tables - a technique used by rootkits and malware.

Methodology:
1. Scan memory for page table entry signatures
2. Validate candidates using multi-field heuristics
3. Cross-reference with official page tables
4. Report discrepancies as potential hidden pages

Authors: Ariana Thomas, Gokul Chaluvadi, Terens Tare
Course: CMSC 654
"""

import struct
from typing import List, Tuple, Iterator, Optional
import sys
import concurrent.futures 

from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.layers import intel

# Define the number of worker threads (retained for performance)
MAX_WORKERS = 8 


class HiddenPages(interfaces.plugins.PluginInterface):
    """
    Detects hidden memory pages by scanning for page structures
    and comparing against official page tables.
    """

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

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
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.candidates_found = 0
        self.candidates_validated = 0
        self.hidden_pages_found = 0

    def _scan_for_pte_signatures(self, layer, scan_size_mb: int) -> Iterator[Tuple[int, int]]:
        """
        Scan memory for potential Page Table Entry signatures.
        """
        # Replaced vollog.info with print
        print(f"[STAGE 1] Scanning {scan_size_mb} MB of memory for PTE signatures...")
        
        scan_size = scan_size_mb * 1024 * 1024 # Convert to bytes
        chunk_size = 1024 * 1024 # Scan in 1MB chunks
        
        last_progress_mb = 0
        
        for offset in range(0, scan_size, 8): # PTEs are 8 bytes on x64
            
            current_progress_mb = offset // chunk_size
            if current_progress_mb > last_progress_mb:
                print(f"[PROGRESS] Scan: {current_progress_mb} MB / {scan_size_mb} MB")
                last_progress_mb = current_progress_mb
                
            try:
                # Read 8 bytes (potential PTE)
                data = layer.read(offset, 8, pad=True)
                qword = struct.unpack('<Q', data)[0]
                
                # Quick check: Present bit must be set
                if qword & 0x1:
                    self.candidates_found += 1
                    yield (offset, qword)
                    
            except Exception as e:
                # Skip inaccessible memory
                continue

    def _validate_pte_candidate(self, offset: int, qword: int) -> Tuple[bool, int, str]:
        """
        Validate if a candidate looks like a real PTE using multiple heuristics.
        """
        score = 0
        max_score = 100
        reasons = []
        
        # Check 1: Present bit (mandatory)
        present = qword & 0x1
        if not present:
            return (False, 0, "Present bit not set")
        score += 20
        reasons.append("Present bit set")
        
        # Check 2: Extract and validate PFN (Physical Frame Number)
        pfn = (qword >> 12) & 0xFFFFFFFFF # Bits 12-47
        
        # PFN shouldn't be all zeros or all ones
        if pfn == 0:
            return (False, score, "PFN is zero")
        if pfn == 0xFFFFFFFFF:
            return (False, score, "PFN is invalid (all 1s)")
        score += 20
        reasons.append("Valid PFN")
        
        # Check 3: Physical address should be page-aligned
        physical_addr = pfn * 0x1000
        if physical_addr % 0x1000 != 0:
            return (False, score, "Not page-aligned")
        score += 15
        reasons.append("Page-aligned")
        
        # Check 4: Reserved bits (52-63) should be zero
        reserved = (qword >> 52) & 0xFFF
        if reserved == 0:
            score += 15
            reasons.append("Reserved bits zero")
        elif reserved < 0x10: # Allow some tolerance
            score += 5
            reasons.append("Reserved bits mostly zero")
        
        # Check 5: Check flag consistency
        rw = (qword >> 1) & 0x1  # Read/Write
        us = (qword >> 2) & 0x1  # User/Supervisor
        accessed = (qword >> 5) & 0x1 # Accessed
        dirty = (qword >> 6) & 0x1  # Dirty
        
        # Can't be dirty without write permission
        if dirty and not rw:
            return (False, score, "Dirty bit set but read-only")
        
        # Reasonable flag combination
        if rw or us or accessed:
            score += 10
            reasons.append("Reasonable flags")
        
        # Check 6: Page size bit
        ps = (qword >> 7) & 0x1
        if ps: # Large page (2MB or 1GB)
            score += 10
            reasons.append("Large page indicator")
        else: # Standard 4KB page
            score += 10
            reasons.append("Standard page size")
        
        # Check 7: Not all flags set (would be suspicious)
        all_flags = qword & 0xFF
        if all_flags == 0xFF:
            return (False, score, "All flags set (suspicious)")
        score += 10
        
        return (True, score, "; ".join(reasons))

    def _get_official_pte(self, kernel_layer, virtual_address: int) -> Optional[int]:
        """
        Look up the official PTE for a virtual address using Volatility's page tables.
        """
        try:
            # Use Volatility's translation mechanism
            # This queries the official page tables
            physical_address, _, page_size = kernel_layer.mapping(
                virtual_address, 
                0x1000,
                ignore_errors=False
            )
            
            # If we got here, the page is mapped
            return physical_address
            
        except exceptions.InvalidAddressException:
            # Page is not mapped in official tables
            return None

    def _is_page_hidden(self, candidate_offset: int, candidate_pte: int, kernel_layer) -> Tuple[bool, str]:
        """
        Determine if the physical address referenced by a candidate PTE
        is accessible but not mapped in official page tables.
        """
        # Extract physical address from candidate PTE
        pfn = (candidate_pte >> 12) & 0xFFFFFFFFF
        physical_address = pfn * 0x1000
        
        # Replaced vollog.debug with print
        print(f"DEBUG: Checking PTE at offset {hex(candidate_offset)}: PFN={hex(pfn)}, Physical={hex(physical_address)}")
        
        # Step 1: Can we access the physical memory it points to?
        try:
            # Try to read from the physical address
            data = kernel_layer.read(physical_address, 16, pad=False)
            memory_exists = True
        except Exception as e:
            # Physical memory doesn't exist or not accessible
            print(f"DEBUG: Physical address {hex(physical_address)} not accessible: {e}")
            return (False, f"PFN points to non-existent memory")
        
        # Step 2: Is this physical address mapped via official page tables?
        test_ranges = [
            # User mode range
            (0x0000000000000000, 0x00007FFFFFFFFFFF, "user-mode"),
            # Kernel mode range 
            (0xFFFF800000000000, 0xFFFFFFFFFFFFFFFF, "kernel-mode"),
        ]
        
        is_mapped = False
        mapped_location = None
        
        for start, end, name in test_ranges:
            # Sample virtual addresses in this range (can't check ALL)
            # Check every 2MB (0x200000) as a heuristic
            for virtual_addr in range(start, min(start + 0x40000000, end), 0x200000):
                try:
                    # Try to translate this virtual address
                    translated_phys, _, _ = kernel_layer.mapping(
                        virtual_addr,
                        0x1000,
                        ignore_errors=False
                    )
                    
                    # Does it map to our target physical address?
                    if translated_phys == physical_address:
                        is_mapped = True
                        mapped_location = f"{name} VA={hex(virtual_addr)}"
                        print(f"DEBUG: Found mapping: {mapped_location}")
                        break
                        
                except Exception:
                    # Virtual address not mapped (expected for most addresses)
                    continue
            
            if is_mapped:
                break
        
        # Step 3: Make determination
        if memory_exists and not is_mapped:
            # Physical memory exists but no virtual mapping found
            # This could be a hidden page!
            return (True, f"Physical memory exists at {hex(physical_address)} but no mapping found")
        elif memory_exists and is_mapped:
            # Physical memory exists and is properly mapped
            return (False, f"Page properly mapped: {mapped_location}")
        else:
            # Shouldn't reach here
            return (False, "Unknown state")

    def _generator(self, kernel_layer) -> Iterator[Tuple]:
        """
        Main detection logic - generate results.
        
        Yields:
            Tuples of detection results
        """
        scan_size = self.config.get('scan-size', 2048)
        min_confidence = self.config.get('confidence', 80)
        
        print("="*60)
        print("Starting Hidden Page Detection")
        print(f"Scan size: {scan_size} MB")
        print(f"Minimum confidence: {min_confidence}%")
        print("="*60)
        
        candidate_log = []
        
        # Phase 1: Scan for signatures
        for offset, qword in self._scan_for_pte_signatures(kernel_layer, scan_size):
            
            # Phase 2: Validate candidate
            is_valid, confidence, reason = self._validate_pte_candidate(offset, qword)
            
            if not is_valid:
                continue
            
            # Log ALL validated candidates (even below threshold)
            candidate_log.append({
                'offset': offset,
                'pte': qword,
                'confidence': confidence
            })
            
            if confidence < min_confidence:
                continue
            
            self.candidates_validated += 1
            
            print(f"Found high-confidence candidate at {hex(offset)}: confidence={confidence}%, PTE={hex(qword)}")
            
            # Phase 3: Check if hidden
            is_hidden, explanation = self._is_page_hidden(offset, qword, kernel_layer)
            
            print(f" -> Hidden check result: {is_hidden} ({explanation})")
            
            if is_hidden:
                self.hidden_pages_found += 1
                
                # Extract details for reporting
                pfn = (qword >> 12) & 0xFFFFFFFFF
                physical_addr = pfn * 0x1000
                flags = self._decode_flags(qword)
                
                yield (0, (
                    format_hints.Hex(offset),
                    format_hints.Hex(physical_addr),
                    format_hints.Hex(qword),
                    confidence,
                    flags,
                    "HIDDEN",
                    explanation
                ))
        
        # Log summary of all candidates
        print(f"\nCandidate distribution:")
        print(f" Total validated: {len(candidate_log)}")
        if candidate_log:
            confidence_scores = [c['confidence'] for c in candidate_log]
            print(f" Average confidence: {sum(confidence_scores)/len(confidence_scores):.1f}%")
            print(f" Max confidence: {max(confidence_scores)}%")
            print(f" Above threshold ({min_confidence}%): {self.candidates_validated}")

    def _decode_flags(self, pte: int) -> str:
        """Decode PTE flags to human-readable string"""
        flags = []
        
        if pte & 0x1:
            flags.append("P") # Present
        if pte & 0x2:
            flags.append("RW") # Read/Write
        if pte & 0x4:
            flags.append("US") # User/Supervisor
        if pte & 0x20:
            flags.append("A") # Accessed
        if pte & 0x40:
            flags.append("D") # Dirty
        if pte & 0x80:
            flags.append("PS") # Page Size
        
        return "|".join(flags) if flags else "NONE"

    def run(self):
        """Main plugin execution"""
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
            self._generator(kernel_layer)
        )
        
        # Log summary
        # Replaced vollog.info with print
        print("="*60)
        print(f"Detection Complete")
        print(f"Candidates found: {self.candidates_found}")
        print(f"Candidates validated: {self.candidates_validated}")
        print(f"Hidden pages detected: {self.hidden_pages_found}")
        print("="*60)
        
        return results