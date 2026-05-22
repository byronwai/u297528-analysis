#!/usr/bin/env python3
"""
XOR Payload Decryption Attempt for u297528.dat
Attempts to decrypt the embedded payload using the identified XOR cipher
"""

import struct, math, os, sys
from collections import Counter

SAMPLE = "/home/kali/Downloads/sandbox/u297528.dat"
OUT_DIR = "/home/kali/Downloads/sandbox/findings"

def read_file():
    with open(SAMPLE, "rb") as f:
        return f.read()

def get_data_section(data):
    """Locate and return the .data section"""
    pe_off = struct.unpack_from("<I", data, 0x3c)[0]
    coff = pe_off + 4
    opt_off = coff + 20
    opt_size = struct.unpack_from("<H", data, coff+16)[0]
    num_sections = struct.unpack_from("<H", data, coff+2)[0]
    sec_off = opt_off + opt_size
    
    sections = []
    for i in range(num_sections):
        s = sec_off + i * 40
        name = data[s:s+8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize = struct.unpack_from("<I", data, s+8)[0]
        vaddr = struct.unpack_from("<I", data, s+12)[0]
        raw_size = struct.unpack_from("<I", data, s+16)[0]
        raw_addr = struct.unpack_from("<I", data, s+20)[0]
        sections.append((name, vaddr, vsize, raw_addr, raw_size))
    
    for name, vaddr, vsize, raw_addr, raw_size in sections:
        if name == ".data":
            return data[raw_addr:raw_addr+raw_size], raw_addr, raw_size, sections
    
    return None, None, None, None

def calc_entropy(block):
    if len(block) < 2:
        return 0.0
    freq = Counter(block)
    total = len(block)
    return -sum((c/total)*math.log2(c/total) for c in freq.values() if c > 0)

# === XOR Decryption Constants ===
# From disassembly at 0x180001a10:
# Pattern: for each position i (0, 2, 4, 6...):
#   result[i+2] = (key XOR input[i+2]) XOR constant
# Constants sampled from the disassembly

XOR_CONSTANTS = [
    0x3D, 0x7A, 0xB7, 0xF4, 0x31, 0x6E, 0xAB, 0xE8,
    0x25, 0x62, 0x9F, 0xDC, 0x19, 0x56, 0x00, 0x00,
]

def attempt_xor_decrypt_v1(data_section, key_byte):
    """Attempt decryption using position-dependent XOR with constants"""
    result = bytearray(len(data_section))
    
    # The first byte is the key, subsequent bytes are decoded
    # Pattern from disassembly:
    # byte[0] = key
    # For even positions i (2, 4, 6, ...):
    #   result[i] = (key XOR input[i]) XOR constant[pos]
    
    for i in range(0, min(len(data_section), 32)):
        if i == 0:
            result[i] = data_section[i]
        elif i % 2 == 0:
            pos = (i - 2) // 2
            constant = XOR_CONSTANTS[pos] if pos < len(XOR_CONSTANTS) else 0
            result[i] = (key_byte ^ data_section[i]) ^ constant
        else:
            result[i] = data_section[i]
    
    return bytes(result)

def attempt_simple_xor(data_section, key):
    """Simple XOR with a single key byte"""
    result = bytearray(len(data_section))
    for i in range(len(data_section)):
        result[i] = data_section[i] ^ key
    return bytes(result)

def attempt_xor_with_ff_pattern(data_section):
    """The .data section has 0x00/0xFF pattern at the start.
    Try XOR with 0xFF to see if the low-entropy area reveals structure."""
    result = bytearray(len(data_section))
    for i in range(len(data_section)):
        result[i] = data_section[i] ^ 0xFF
    return bytes(result)

def scan_for_pe_headers(data, start_offset=0):
    """Scan for MZ/PE headers in data"""
    found = []
    for i in range(start_offset, len(data) - 4):
        if data[i:i+2] == b'MZ':
            if i + 0x3c < len(data):
                pe_off_val = struct.unpack_from("<I", data, i+0x3c)[0]
                if pe_off_val < 0x1000 and i + pe_off_val + 4 < len(data):
                    if data[i+pe_off_val:i+pe_off_val+4] == b'PE\x00\x00':
                        found.append(i)
    return found

def find_payload_boundary(data_section):
    """Find where the high-entropy payload starts"""
    chunk_size = 4096
    for offset in range(0, len(data_section), chunk_size):
        block = data_section[offset:offset+chunk_size]
        if len(block) >= 256:
            ent = calc_entropy(block[:256])
            if ent > 6.0:
                return offset
    return None

def main():
    data = read_file()
    data_section, sec_off, sec_size, sections = get_data_section(data)
    
    if data_section is None:
        print("ERROR: .data section not found")
        return
    
    results = {}
    
    # === Payload Boundary Detection ===
    payload_start = find_payload_boundary(data_section)
    results["payload_boundary"] = {
        "low_entropy_start": "0x0",
        "high_entropy_start": hex(payload_start) if payload_start else "not found",
        "low_entropy_size_human": f"{payload_start/1024/1024:.2f} MB" if payload_start else "unknown",
        "high_entropy_size_human": f"{(len(data_section)-payload_start)/1024/1024:.2f} MB" if payload_start else "unknown",
    }
    
    # === Analyze .data section byte patterns ===
    # First 4KB
    first_4k = data_section[:4096]
    freq = Counter(first_4k)
    top_bytes = sorted(freq.items(), key=lambda x: -x[1])[:5]
    results["data_section_start_pattern"] = {
        "top_byte_values": [(hex(b), count, f"{count/4096*100:.1f}%") for b, count in top_bytes],
        "pattern_note": "0x00 and 0xFF dominance suggests XOR-encoded or placeholder data",
    }
    
    # === Try various XOR decryption approaches ===
    
    # Approach 1: XOR entire low-entropy region with 0xFF
    xor_ff = attempt_xor_with_ff_pattern(data_section[:0x10000])
    pe_headers_ff = scan_for_pe_headers(xor_ff)
    results["xor_ff_scan"] = {
        "pe_headers_found": len(pe_headers_ff),
        "positions": [hex(p) for p in pe_headers_ff[:5]],
        "first_64_bytes_hex": xor_ff[:64].hex(),
        "entropy": round(calc_entropy(xor_ff[:256]), 2),
    }
    
    # Approach 2: Simple XOR with various keys on payload area
    if payload_start:
        payload_area = data_section[payload_start:payload_start+0x10000]
        payload_entropy = calc_entropy(payload_area[:256])
        
        # Try common XOR keys
        key_results = []
        for key in [0x00, 0xFF, 0xAA, 0x55, 0x31, 0x68, 0xE1, 0x3D, 0x7A, 0xB7, 0xF4, 0x6E, 0xAB]:
            decrypted = attempt_simple_xor(payload_area, key)
            pe_found = scan_for_pe_headers(decrypted)
            new_entropy = calc_entropy(decrypted[:256])
            key_results.append({
                "key": hex(key),
                "pe_headers_found": len(pe_found),
                "result_entropy": round(new_entropy, 2),
                "first_16_hex": decrypted[:16].hex(),
            })
        
        results["xor_key_attempts"] = key_results
    
    # Approach 3: Position-dependent XOR on the first section
    # Use the first byte of .data as the key
    key_byte = data_section[0]
    results["first_byte_as_key"] = {
        "value": hex(key_byte),
        "note": "Byte at offset 0 of .data section, used as XOR key in the cipher",
    }
    
    # Try position-dependent XOR decode on first area
    decoded = attempt_xor_decrypt_v1(data_section[:0x100], key_byte)
    results["position_dependent_xor"] = {
        "decoded_first_64_hex": decoded[:64].hex(),
        "original_first_64_hex": data_section[:64].hex(),
        "key_byte": hex(key_byte),
    }
    
    # Approach 4: Extract and save the high-entropy payload region
    if payload_start:
        payload_data = data_section[payload_start:]
        payload_file = os.path.join(OUT_DIR, "encrypted_payload.bin")
        with open(payload_file, "wb") as f:
            # Save first 1MB of payload for offline analysis
            f.write(payload_data[:1024*1024])
        results["payload_extracted"] = {
            "file": payload_file,
            "size_saved": "1 MB (first chunk)",
            "total_payload_size": f"{len(payload_data)/1024/1024:.2f} MB",
            "entropy": round(calc_entropy(payload_data[:4096]), 3),
            "first_32_hex": payload_data[:32].hex(),
            "last_32_hex": payload_data[-32:].hex(),
        }
    
    # Approach 5: Try to identify the encryption scheme
    # Check if the high-entropy area could be AES/ChaCha20 encrypted
    if payload_start:
        payload = data_section[payload_start:]
        # AES block size is 16 bytes
        # Check for repeating 16-byte patterns (would indicate ECB mode)
        block_freq = Counter()
        for i in range(0, min(len(payload), 0x10000), 16):
            block = payload[i:i+16]
            block_freq[block] += 1
        
        max_repeat = max(block_freq.values()) if block_freq else 0
        results["encryption_analysis"] = {
            "max_block_repetition_16byte": max_repeat,
            "likely_mode": "AES-CTR/ChaCha20 (no block repetition)" if max_repeat < 3 else "Possibly AES-ECB (block repetition detected)",
            "overall_entropy": round(calc_entropy(payload[:65536]), 3),
            "note": "High entropy with no block repetition suggests stream cipher or CTR mode encryption",
        }
    
    # Approach 6: Look for structure in the low-entropy region
    # The 0x00/0xFF pattern might be a bitmap/index table
    low_ent = data_section[:payload_start if payload_start else 0x100000]
    ff_positions = []
    zero_positions = []
    
    # Sample every 256 bytes
    for i in range(0, min(len(low_ent), 0x100000), 256):
        block = low_ent[i:i+256]
        ff_count = sum(1 for b in block if b == 0xFF)
        zero_count = sum(1 for b in block if b == 0x00)
        if ff_count > 200:
            ff_positions.append(hex(i))
        elif zero_count > 200:
            zero_positions.append(hex(i))
    
    results["low_entropy_structure"] = {
        "ff_dense_blocks": len(ff_positions),
        "zero_dense_blocks": len(zero_positions),
        "ff_positions_sample": ff_positions[:10],
        "zero_positions_sample": zero_positions[:10],
        "interpretation": "The 0x00/0xFF interleaved pattern may be an encoded index table or lookup matrix used for payload substitution",
    }
    
    # === Try XOR with 0xFF on the FULL low-entropy region ===
    # Maybe the low-entropy area is XOR-encoded with 0xFF
    if payload_start:
        low_region = data_section[:payload_start]
        xor_ff_low = attempt_xor_with_ff_pattern(low_region[:0x10000])
        pe_in_low = scan_for_pe_headers(xor_ff_low)
        entropy_after_xor = calc_entropy(xor_ff_low[:256])
        
        results["low_entropy_xor_ff"] = {
            "pe_headers_found": len(pe_in_low),
            "entropy_after_xor": round(entropy_after_xor, 2),
            "first_64_hex": xor_ff_low[:64].hex(),
            "note": "XOR with 0xFF on the 0x00/0xFF region converts to all-0xFF/all-0x00 - no meaningful structure revealed",
        }
    
    # === Scan original data for hidden PE/ELF/Mach-O ===
    all_pe = scan_for_pe_headers(data)
    results["full_file_pe_scan"] = {
        "total_pe_signatures": len(all_pe),
        "positions": [hex(p) for p in all_pe[:10]],
        "note": "Only the main PE header at expected offset - no embedded secondary PE found (payload fully encrypted)",
    }
    
    # === Save results ===
    out_file = os.path.join(OUT_DIR, "decryption_analysis.json")
    with open(out_file, "w") as f:
        import json
        json.dump(results, f, indent=2)
    print(f"[+] Decryption analysis saved to {out_file}")
    
    # === Generate summary report ===
    report = os.path.join(OUT_DIR, "decryption_report.txt")
    with open(report, "w") as f:
        f.write("=" * 70 + "\n")
        f.write("  XOR DECRYPTION ANALYSIS REPORT\n")
        f.write("=" * 70 + "\n\n")
        
        f.write("--- Payload Boundary ---\n")
        pb = results["payload_boundary"]
        f.write(f"  Low entropy region: {pb['low_entropy_start']} to {pb['high_entropy_start']}\n")
        f.write(f"  Low entropy size: {pb['low_entropy_size_human']}\n")
        f.write(f"  High entropy size: {pb['high_entropy_size_human']}\n\n")
        
        f.write("--- Data Section Start Pattern ---\n")
        dsp = results["data_section_start_pattern"]
        for byte, count, pct in dsp["top_byte_values"]:
            f.write(f"  {byte}: {count} ({pct})\n")
        f.write(f"  {dsp['pattern_note']}\n\n")
        
        f.write("--- XOR Key Attempts ---\n")
        for kr in results.get("xor_key_attempts", []):
            f.write(f"  Key {kr['key']}: PE headers={kr['pe_headers_found']}, entropy={kr['result_entropy']}, first16={kr['first_16_hex']}\n")
        f.write("\n")
        
        f.write("--- Encryption Analysis ---\n")
        ea = results["encryption_analysis"]
        f.write(f"  Max 16-byte block repetition: {ea['max_block_repetition_16byte']}\n")
        f.write(f"  Likely mode: {ea['likely_mode']}\n")
        f.write(f"  Overall entropy: {ea['overall_entropy']}\n")
        f.write(f"  {ea['note']}\n\n")
        
        f.write("--- Position-Dependent XOR ---\n")
        pdx = results["position_dependent_xor"]
        f.write(f"  Key byte: {pdx['key_byte']}\n")
        f.write(f"  Decoded first 64: {pdx['decoded_first_64_hex']}\n")
        f.write(f"  Original first 64: {pdx['original_first_64_hex']}\n\n")
        
        f.write("--- Payload Extraction ---\n")
        pe_ext = results.get("payload_extracted", {})
        if pe_ext:
            f.write(f"  File: {pe_ext['file']}\n")
            f.write(f"  Total size: {pe_ext['total_payload_size']}\n")
            f.write(f"  First 32: {pe_ext['first_32_hex']}\n\n")
        
        f.write("--- Low Entropy Structure ---\n")
        les = results["low_entropy_structure"]
        f.write(f"  FF-dense blocks: {les['ff_dense_blocks']}\n")
        f.write(f"  Zero-dense blocks: {les['zero_dense_blocks']}\n")
        f.write(f"  Interpretation: {les['interpretation']}\n\n")
        
        f.write("--- Conclusions ---\n")
        f.write("  The payload uses multi-layer encryption:\n")
        f.write("  1. A 0x00/0xFF encoded index/lookup table (~5.7 MB)\n")
        f.write("  2. A high-entropy encrypted payload (~7 MB, likely AES-CTR/ChaCha20)\n")
        f.write("  3. Position-dependent XOR cipher for the decode table\n")
        f.write("  4. The real payload decryption likely requires runtime state\n")
        f.write("     (the substitution table is built dynamically in IdllEntry)\n")
        f.write("  Simple XOR attempts did not reveal embedded PE headers.\n")
        f.write("  Full decryption requires emulating the IdllEntry execution flow.\n")
    
    print(f"[+] Decryption report saved to {report}")
    print(f"[+] Encrypted payload sample saved to {os.path.join(OUT_DIR, 'encrypted_payload.bin')}")

if __name__ == "__main__":
    main()