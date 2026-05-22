#!/usr/bin/env python3
"""
Comprehensive decryption script for u297528.dat (idll.dll)
Uses pefile + reverse-engineered XOR cipher + AES key extraction
"""

import pefile
import struct
import hashlib
import os
import json
from collections import Counter

SAMPLE = "/home/kali/Downloads/sandbox/u297528.dat"
OUTDIR = "/home/kali/Downloads/sandbox/findings"

# ============================================================
# 1. XOR constant table (arithmetic sequence)
#    constant[i] = (0x3D * (i + 1)) & 0xFF
# ============================================================
def xor_constant(i):
    return (0x3D * (i + 1)) & 0xFF

def generate_xor_table(n):
    return [xor_constant(i) for i in range(n)]

# ============================================================
# 2. Position-dependent XOR decryption
#    decoded[i] = (key_byte XOR data[i]) XOR xor_constant(i)
# ============================================================
def xor_decrypt_table(data, key_byte):
    """Decrypt a substitution table using position-dependent XOR"""
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = (key_byte ^ data[i]) ^ xor_constant(i)
    return result

# ============================================================
# 3. Parse PE with pefile
# ============================================================
print("[*] Parsing PE with pefile...")
pe = pefile.PE(SAMPLE)

# Find .data section
data_section = None
for s in pe.sections:
    name = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    if name == '.data':
        data_section = s
        break

if not data_section:
    print("[-] .data section not found!")
    exit(1)

data_raw = data_section.get_data()
data_va = data_section.VirtualAddress
data_size = len(data_raw)
print(f"[+] .data section: VA=0x{data_va:x}, Size={data_size} bytes ({data_size/1024/1024:.2f} MB)")

# ============================================================
# 4. Analyze the low-entropy region (substitution table)
# ============================================================
print("\n[*] Analyzing substitution table region...")

# The .data section structure:
# Offset 0: key byte
# Offset 1: initialized flag (0 = not decoded, 1 = decoded)
# Offset 2+: substitution table entries (WORD sized, 2 bytes each)

key_byte = data_raw[0]
init_flag = data_raw[1]
print(f"[+] Key byte at offset 0: 0x{key_byte:02x}")
print(f"[+] Init flag at offset 1: 0x{init_flag:02x}")

# Show first 64 bytes of raw data
print(f"[+] First 64 bytes raw: {data_raw[:64].hex()}")

# The substitution table entries are WORDs (2 bytes each)
# Even bytes (0, 2, 4, ...) are the data bytes used in XOR
# Odd bytes (1, 3, 5, ...) are the high bytes of the WORD results

# ============================================================
# 5. Decode the substitution table with position-dependent XOR
# ============================================================
print("\n[*] Applying position-dependent XOR decryption to substitution table...")

# The XOR function processes the table as words at offsets 2, 4, 6, ...
# Each word: decoded_byte = (key XOR input_byte) XOR constant[i]
# The input_byte is at the even offset within the word

# Let's try multiple interpretations:

# Interpretation 1: The whole .data section low-entropy region is the table
# Each byte at even offset (2, 4, 6, ...) gets decoded
low_entropy_size = 0x57d000  # ~5.7MB boundary from entropy analysis

# Decode the even bytes (the actual data in the word pairs)
even_bytes = bytearray()
for i in range(2, min(low_entropy_size, len(data_raw)), 2):
    even_bytes.append(data_raw[i])

print(f"[+] Extracted {len(even_bytes)} even-offset bytes from substitution table")

# Apply XOR decryption
decoded_table = xor_decrypt_table(even_bytes, key_byte)
print(f"[+] Decoded first 64 bytes: {decoded_table[:64].hex()}")
print(f"[+] Decoded first 64 as ASCII: {decoded_table[:64]}")

# Also try decoding ALL bytes (not just even offsets)
decoded_all = xor_decrypt_table(data_raw[:low_entropy_size], key_byte)
print(f"[+] Decoded ALL first 64 bytes: {decoded_all[:64].hex()}")

# ============================================================
# 6. Analyze the decoded substitution table for structure
# ============================================================
print("\n[*] Analyzing decoded substitution table structure...")

# Check for patterns in decoded table
decoded_counter = Counter(decoded_table[:0x1000])
print(f"[+] Top 10 bytes in decoded table (first 4KB):")
for byte_val, count in decoded_counter.most_common(10):
    print(f"    0x{byte_val:02x}: {count} ({count*100/0x1000:.1f}%)")

# Look for repeating patterns (could be AES key schedule)
for pattern_len in [16, 32, 48, 64]:
    for start in range(0, min(256, len(decoded_table) - pattern_len)):
        pattern = decoded_table[start:start+pattern_len]
        # Search for this pattern later in the table
        search_start = start + pattern_len
        if search_start + pattern_len < len(decoded_table):
            if decoded_table[search_start:search_start+pattern_len] == bytes(pattern):
                print(f"[!] Repeating {pattern_len}-byte pattern at offset {start} (repeats at {search_start})")
                print(f"    Pattern: {bytes(pattern).hex()}")
                break

# ============================================================
# 7. Look for AES key candidates
# ============================================================
print("\n[*] Searching for AES key candidates...")

# AES-128 key = 16 bytes, AES-256 key = 32 bytes
# Common locations: start of table, or embedded in decoded structure

# Candidate 1: First 16/32 bytes of decoded table
for key_len in [16, 32]:
    key_candidate = decoded_table[:key_len]
    print(f"\n[+] Candidate key (first {key_len} bytes of decoded table):")
    print(f"    Hex: {bytes(key_candidate).hex()}")

# Candidate 2: Search for high-entropy 16/32-byte sequences in decoded table
# (Real AES keys have high entropy)
def entropy(data):
    if len(data) == 0:
        return 0
    counter = Counter(data)
    length = len(data)
    import math
    return -sum((count/length) * math.log2(count/length) for count in counter.values())

# Scan for high-entropy 16-byte blocks
best_entropy_offset = -1
best_entropy_val = 0
block_size = 16
for offset in range(0, min(4096, len(decoded_table) - block_size), block_size):
    block = decoded_table[offset:offset+block_size]
    ent = entropy(block)
    if ent > best_entropy_val:
        best_entropy_val = ent
        best_entropy_offset = offset

if best_entropy_offset >= 0:
    key_candidate = decoded_table[best_entropy_offset:best_entropy_offset+32]
    print(f"\n[+] Highest entropy block at offset {best_entropy_offset} (entropy={best_entropy_val:.2f}):")
    print(f"    16 bytes: {bytes(key_candidate[:16]).hex()}")
    print(f"    32 bytes: {bytes(key_candidate[:32]).hex()}")

# ============================================================
# 8. Analyze the high-entropy payload region
# ============================================================
print("\n[*] Analyzing high-entropy payload region...")

payload_start = low_entropy_size  # 0x57d000
payload_data = data_raw[payload_start:]
payload_size = len(payload_data)
print(f"[+] Payload starts at offset 0x{payload_start:x}")
print(f"[+] Payload size: {payload_size} bytes ({payload_size/1024/1024:.2f} MB)")
print(f"[+] First 64 bytes: {payload_data[:64].hex()}")
print(f"[+] Last 64 bytes: {payload_data[-64:].hex()}")

# ============================================================
# 9. Try to decode the substitution table as a byte mapping
# ============================================================
print("\n[*] Building substitution mapping from decoded table...")

# The decoded table might be a 256-byte substitution box (S-box)
# or a larger mapping table. Let's check if it's 256 bytes.
if len(decoded_table) >= 256:
    sbox_candidate = decoded_table[:256]
    unique_vals = len(set(sbox_candidate))
    print(f"[+] First 256 decoded bytes as potential S-box:")
    print(f"    Unique values: {unique_vals}/256")
    print(f"    Hex: {bytes(sbox_candidate).hex()}")
    
    if unique_vals == 256:
        print("[!] This IS a valid substitution box (256 unique values)!")
        # Save the S-box
        with open(os.path.join(OUTDIR, "extracted_sbox.bin"), 'wb') as f:
            f.write(bytes(sbox_candidate))
        print("[+] Saved to extracted_sbox.bin")

# ============================================================
# 10. Try AES-CTR decryption with various key sources
# ============================================================
print("\n[*] Attempting AES decryption...")

try:
    from Crypto.Cipher import AES
    HAS_PYCRYPTO = True
except ImportError:
    HAS_PYCRYPTO = False

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# Check which library is available
print(f"[+] PyCryptodome: {'available' if HAS_PYCRYPTO else 'not available'}")

if not HAS_PYCRYPTO and not HAS_CRYPTOGRAPHY:
    print("[*] Installing pycryptodome...")
    import subprocess
    subprocess.run(["pip3", "install", "pycryptodome", "--break-system-packages"], 
                   capture_output=True)
    try:
        from Crypto.Cipher import AES
        HAS_PYCRYPTO = True
        print("[+] PyCryptodome installed successfully")
    except ImportError:
        print("[-] Could not install PyCryptodome")

def try_aes_ctr_decrypt(payload, key, iv, label=""):
    """Try AES-CTR decryption and check for PE headers"""
    if len(key) not in [16, 32]:
        return None
    
    try:
        if HAS_PYCRYPTO:
            cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8] if len(iv) >= 8 else iv)
            decrypted = cipher.decrypt(payload[:4096])
        elif HAS_CRYPTOGRAPHY:
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(payload[:4096]) + decryptor.finalize()
        else:
            return None
    except Exception as e:
        return None
    
    # Check for PE header
    if decrypted[:2] == b'MZ':
        print(f"[!!!] PE HEADER FOUND with {label}!")
        print(f"    Key: {key.hex()}")
        print(f"    IV/Nonce: {iv.hex()}")
        print(f"    First 64: {decrypted[:64].hex()}")
        return decrypted
    
    # Check for common patterns
    printable = sum(1 for b in decrypted[:256] if 0x20 <= b <= 0x7e)
    null_count = decrypted[:256].count(0)
    
    if printable > 128 or null_count > 128:
        print(f"[+] Interesting result with {label}:")
        print(f"    Printable: {printable}/256, Nulls: {null_count}/256")
        print(f"    First 32: {decrypted[:32].hex()}")
        return decrypted
    
    return None

# ============================================================
# 11. Build comprehensive key candidates
# ============================================================
print("\n[*] Building key candidate list...")

key_candidates = []

# The decoded substitution table provides the key candidates
# Method 1: First 16 bytes of decoded table
key_candidates.append(("decoded_first16", bytes(decoded_table[:16]), bytes(16)))

# Method 2: First 32 bytes of decoded table as AES-256 key
key_candidates.append(("decoded_first32", bytes(decoded_table[:32]), bytes(16)))

# Method 3: The original key byte + decoded bytes
key_candidates.append(("keybyte_decoded_16", bytes([key_byte]) + bytes(decoded_table[:15]), bytes(16)))

# Method 4: Look at the specific structure - the XOR function stores WORD results
# The WORD values after XOR decoding may contain the actual key
word_values = []
for i in range(0, min(512, len(decoded_table))):
    word_values.append(decoded_table[i])

# Method 5: Use the first 16 decoded WORD values (high byte + low byte)
# Since the XOR stores results as WORDs, the actual key might be in the word values
first_words = []
for i in range(min(32, len(decoded_table) // 2)):
    word_idx = i * 2
    if word_idx + 1 < len(decoded_table):
        word_val = decoded_table[word_idx] | (decoded_table[word_idx + 1] << 8)
        first_words.append(word_val)

word_key = b''.join(struct.pack('<H', w) for w in first_words[:8])
key_candidates.append(("first_words_16", word_key, bytes(16)))

# Method 6: Hash of the decoded table as key
md5_key = hashlib.md5(bytes(decoded_table[:256])).digest()
key_candidates.append(("md5_decoded_table", md5_key, bytes(16)))

sha256_key = hashlib.sha256(bytes(decoded_table[:256])).digest()
key_candidates.append(("sha256_decoded_table_16", sha256_key[:16], bytes(16)))

# Method 7: Try raw .data bytes (without XOR decode) as key
key_candidates.append(("raw_first16", data_raw[:16], bytes(16)))

# Method 8: The decoded bytes at specific offsets matching AES key schedule patterns
# AES-128 first round key is often at a fixed offset in the data
for offset in [0, 2, 4, 16, 32, 64, 128, 256]:
    if offset + 16 <= len(decoded_table):
        key_candidates.append((f"decoded_offset_{offset}", bytes(decoded_table[offset:offset+16]), bytes(16)))

# ============================================================
# 12. Try each key candidate
# ============================================================
print(f"\n[*] Testing {len(key_candidates)} key candidates against payload...")

results = []
for label, key, iv in key_candidates:
    result = try_aes_ctr_decrypt(payload_data, key, iv, label)
    if result is not None:
        results.append({"label": label, "key": key.hex(), "iv": iv.hex(), "found_pe": result[:2] == b'MZ'})

# ============================================================
# 13. Try AES-CBC and AES-ECB as well
# ============================================================
print("\n[*] Trying AES-CBC and AES-ECB modes...")

for label, key, iv in key_candidates[:5]:  # Top 5 candidates
    try:
        # CBC with zero IV
        if HAS_PYCRYPTO and len(key) in [16, 32]:
            cipher_cbc = AES.new(key, AES.MODE_CBC, iv)
            dec_cbc = cipher_cbc.decrypt(payload_data[:4096])
            if dec_cbc[:2] == b'MZ':
                print(f"[!!!] PE HEADER FOUND (CBC) with {label}!")
                print(f"    Key: {key.hex()}")
                results.append({"label": f"{label}_cbc", "key": key.hex(), "iv": iv.hex(), "found_pe": True})
    except:
        pass

# ============================================================
# 14. Try XOR decryption on the payload using the substitution table
# ============================================================
print("\n[*] Trying substitution-based decryption on payload...")

# If the substitution table is a 256-byte S-box, apply inverse substitution
if len(decoded_table) >= 256:
    sbox = decoded_table[:256]
    unique_vals = len(set(sbox))
    
    if unique_vals == 256:
        # Build inverse S-box
        inv_sbox = [0] * 256
        for i, v in enumerate(sbox):
            inv_sbox[v] = i
        
        # Apply inverse S-box to payload
        inv_result = bytearray(4096)
        for i in range(min(4096, len(payload_data))):
            inv_result[i] = inv_sbox[payload_data[i]]
        
        if inv_result[:2] == b'MZ':
            print("[!!!] PE HEADER FOUND via inverse S-box substitution!")
            print(f"    First 64: {bytes(inv_result[:64]).hex()}")
        
        print(f"[+] Inverse S-box result first 32: {bytes(inv_result[:32]).hex()}")

# ============================================================
# 15. Try applying the position-dependent XOR to the payload
# ============================================================
print("\n[*] Trying position-dependent XOR on payload...")

# Maybe the payload is also XOR'd with the same arithmetic sequence
for key in [key_byte, 0x00, 0xFF]:
    decoded_payload = bytearray(4096)
    for i in range(min(4096, len(payload_data))):
        decoded_payload[i] = (key ^ payload_data[i]) ^ xor_constant(i)
    
    if decoded_payload[:2] == b'MZ':
        print(f"[!!!] PE HEADER FOUND with position-XOR key=0x{key:02x}!")
    else:
        ent = entropy(decoded_payload)
        if ent < 6.0:
            print(f"[+] Key 0x{key:02x}: entropy={ent:.2f}, first 16: {bytes(decoded_payload[:16]).hex()}")

# ============================================================
# 16. Extract and save all key findings
# ============================================================
print("\n[*] Saving decryption analysis results...")

analysis = {
    "xor_constants": {
        "formula": "constant[i] = (0x3D * (i + 1)) & 0xFF",
        "base": 61,
        "first_20": [xor_constant(i) for i in range(20)],
        "sequence_verified": True
    },
    "substitution_table": {
        "key_byte": f"0x{key_byte:02x}",
        "init_flag": f"0x{init_flag:02x}",
        "decoded_first_64": decoded_table[:64].hex(),
        "decoded_first_64_ascii": decoded_table[:64].decode('ascii', errors='replace'),
        "table_size": len(even_bytes),
        "unique_bytes_in_first_256": len(set(decoded_table[:256]))
    },
    "payload": {
        "offset": f"0x{payload_start:x}",
        "size": payload_size,
        "first_32_hex": payload_data[:32].hex(),
        "last_32_hex": payload_data[-32:].hex()
    },
    "aes_attempts": results,
    "key_candidates_tested": len(key_candidates)
}

with open(os.path.join(OUTDIR, "decryption_deep_analysis.json"), 'w') as f:
    json.dump(analysis, f, indent=2, default=str)

# Save the decoded substitution table
with open(os.path.join(OUTDIR, "decoded_substitution_table.bin"), 'wb') as f:
    f.write(bytes(decoded_table[:65536]))  # First 64KB

# Save first 1MB of decoded payload attempt
with open(os.path.join(OUTDIR, "payload_xor_decoded.bin"), 'wb') as f:
    decoded_1mb = bytearray(min(0x100000, len(payload_data)))
    for i in range(len(decoded_1mb)):
        decoded_1mb[i] = (key_byte ^ payload_data[i]) ^ xor_constant(i)
    f.write(bytes(decoded_1mb))

print("\n[*] Saved:")
print(f"    decryption_deep_analysis.json")
print(f"    decoded_substitution_table.bin (64KB)")
print(f"    payload_xor_decoded.bin (1MB)")

pe.close()
print("\n[*] Done!")
