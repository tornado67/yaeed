#!/usr/bin/env python3

import argparse
import re
import subprocess
import os
import sys
from typing import List, Tuple, Optional, Dict

EXCEPTIONS = [
    "Illegal instruction",
    "SYSCALL instruction",
    "InstructionFetchError: Processor internal physical address or data error during instruction fetch",
    "LoadStoreError: Processor internal physical address or data error during load or store",
    "Level1Interrupt: Level-1 interrupt as indicated by set level-1 bits in the INTERRUPT register",
    "Alloca: MOVSP instruction, if caller's registers are not in the register file",
    "IntegerDivideByZero: QUOS, QUOU, REMS, or REMU divisor operand is zero",
    "reserved",
    "Privileged: Attempt to execute a privileged operation when CRING ? 0",
    "LoadStoreAlignmentCause: Load or store to an unaligned address",
    "reserved",
    "reserved",
    "InstrPIFDataError: PIF data error during instruction fetch",
    "LoadStorePIFDataError: Synchronous PIF data error during LoadStore access",
    "InstrPIFAddrError: PIF address error during instruction fetch",
    "LoadStorePIFAddrError: Synchronous PIF address error during LoadStore access",
    "InstTLBMiss: Error during Instruction TLB refill",
    "InstTLBMultiHit: Multiple instruction TLB entries matched",
    "InstFetchPrivilege: An instruction fetch referenced a virtual address at a ring level less than CRING",
    "reserved",
    "InstFetchProhibited: An instruction fetch referenced a page mapped with an attribute that does not permit instruction fetch",
    "reserved",
    "reserved",
    "reserved",
    "LoadStoreTLBMiss: Error during TLB refill for a load or store",
    "LoadStoreTLBMultiHit: Multiple TLB entries matched for a load or store",
    "LoadStorePrivilege: A load or store referenced a virtual address at a ring level less than CRING",
    "reserved",
    "LoadProhibited: A load referenced a page mapped with an attribute that does not permit loads",
    "StoreProhibited: A store referenced a page mapped with an attribute that does not permit stores",
]

def parse_exception(stacktrace: str) -> Optional[Tuple[str, int]]:
    """Parse exception code from stacktrace."""
    match = re.search(r"Exception \(([0-9]+)\)", stacktrace)
    if match:
        code = int(match.group(1))
        if code < len(EXCEPTIONS) and EXCEPTIONS[code] != "reserved":
            return (EXCEPTIONS[code], code)
    return None

def parse_registers(stacktrace: str) -> Dict[str, str]:
    """Parse PC and EXCVADDR from stacktrace."""
    registers = {}
    
    pc_match = re.search(r"PC\s*:\s*(0x[0-9a-f]{8})", stacktrace, re.IGNORECASE)
    if pc_match:
        registers["PC"] = pc_match.group(1)
    excvaddr_match = re.search(r"EXCVADDR\s*:\s*(0x[0-9a-f]{8})", stacktrace, re.IGNORECASE)
    if excvaddr_match:
        registers["EXCVADDR"] = excvaddr_match.group(1)

    if not pc_match:
        pc_match = re.search(r"epc1=(0x[0-9a-f]{8})", stacktrace, re.IGNORECASE)
        if pc_match:
            registers["PC"] = pc_match.group(1)
    if not excvaddr_match:
        excvaddr_match = re.search(r"excvaddr=(0x[0-9a-f]{8})", stacktrace, re.IGNORECASE)
        if excvaddr_match:
            registers["EXCVADDR"] = excvaddr_match.group(1)
    
    return registers

def parse_stacktrace(stacktrace: str) -> Optional[str]:
    """Extract stacktrace content from ESP32 or ESP8266 format."""
    # ESP32 Backtrace
    match = re.search(r"Backtrace:(.*)", stacktrace)
    if match:
        return match.group(1).strip()
    
    # ESP8266 >>>stack>>>
    start_idx = stacktrace.find(">>>stack>>>")
    end_idx = stacktrace.find("<<<stack<<<")
    if start_idx != -1 and end_idx != -1 and start_idx < end_idx:
        return stacktrace[start_idx + len(">>>stack>>>"):end_idx].strip()
    
    return None

def parse_instruction_addresses(content: str) -> List[str]:
    """Extract valid instruction addresses from stacktrace."""
    # range 0x40000000 to 0x43ffffff
    addresses = re.findall(r"4[0-3][0-9a-f]{6}", content, re.IGNORECASE)
    return [f"0x{addr}" for addr in addresses]

def decode_addresses(elf_path: str, addresses: List[str], addr2line_path: str, verbose: bool = False) -> List[Tuple[str, str]]:
    """Decode addresses using addr2line."""
    if not addresses:
        return []

    cmd = [addr2line_path, "-e", elf_path, "-a", "-f", "-C", "-s"]
    cmd.extend(addresses)
    
    try:
        if verbose:
            print(f"Running: {' '.join(cmd)}", file=sys.stderr)
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout.strip().splitlines()
        
        if verbose:
            print(f"addr2line output:\n{result.stdout}", file=sys.stderr)
        
        decoded = []
        i = 0
        while i < len(output):
            address_match = re.match(r"^(0x[0-9a-f]{8})$", output[i].strip())
            if not address_match:
                i += 1
                continue
            address = address_match.group(1)
            i += 1

            if i >= len(output):
                decoded.append((address, "Unknown (incomplete output)"))
                break
            
            function = output[i].strip()
            i += 1
            if i < len(output) and ":" in output[i]:
                file_line = output[i].strip()
                i += 1
            else:
                file_line = "??:0"
            
            if function == "??" and file_line == "??:0":
                decoded.append((address, "Unknown function"))
            else:
                decoded.append((address, f"{function} at {file_line}"))
        
        address_set = set(addresses)
        decoded_set = set(d[0] for d in decoded)
        for addr in address_set - decoded_set:
            decoded.append((addr, "Error decoding address"))
        
        return decoded
    except subprocess.CalledProcessError as e:
        if verbose:
            print(f"Error running addr2line: {e}\nOutput: {e.output}", file=sys.stderr)
        return [(addr, "Error decoding address") for addr in addresses]

def main():
    parser = argparse.ArgumentParser(description="Decode ESP32/ESP8266 stack traces.")
    parser.add_argument("-e","--elf", help="Path to the ELF file from the sketch compilation.")
    parser.add_argument("-s","--tracefile", help="Path to the file containing the stack trace.")
    parser.add_argument("-t","--trace", help="Stack trace content.")
    parser.add_argument("--addr2line", default="xtensa-esp32-elf-addr2line",
                        help="Path to addr2line executable (default: xtensa-esp32-elf-addr2line in PATH).")
    parser.add_argument("--verbose", action="store_true", help="Print verbose debugging output.")
    
    args = parser.parse_args()

    if not os.path.isfile(args.elf):
        print(f"Error: ELF file '{args.elf}' does not exist.", file=sys.stderr)
        sys.exit(1)
    if args.tracefile:
        if not os.path.isfile(args.tracefile):
            print(f"Error: Stacktrace file '{args.tracefile}' does not exist.", file=sys.stderr)
            sys.exit(1)
    if not os.path.isfile(args.addr2line) and not shutil.which(args.addr2line):
        print(f"Error: addr2line executable '{args.addr2line}' not found.", file=sys.stderr)
        sys.exit(1)
    if args.tracefile:
        with open(args.tracefile, "r") as f:
            stacktrace = f.read()
    elif args.trace:
        stacktrace = args.trace

    exception = parse_exception(stacktrace)
    if exception:
        message, code = exception
        print(f"Exception {code}: {message}")

    registers = parse_registers(stacktrace)
    for reg, addr in registers.items():
        print(f"{reg}: {addr}")

    content = parse_stacktrace(stacktrace)
    if not content:
        print("Error: Could not recognize stack trace/backtrace.", file=sys.stderr)
        sys.exit(1)

    addresses = parse_instruction_addresses(content)
    if not addresses:
        print("Error: No valid instruction addresses found in stack trace.", file=sys.stderr)
        sys.exit(1)

    decoded_lines = decode_addresses(args.elf, addresses, args.addr2line, args.verbose)
    if decoded_lines:
        print("\nDecoded Stack Trace:")
        for address, line in decoded_lines:
            print(f"{address}: {line}")

if __name__ == "__main__":
    import shutil
    main()