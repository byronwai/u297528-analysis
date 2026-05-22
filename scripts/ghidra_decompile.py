# Ghidra headless decompile script for u297528.dat (idll.dll)
# Extracts decompiled code from key functions for decryption analysis

from ghidra.program.model.listing import CodeUnit
from ghidra.app.decompiler import DecompInterface
import json

OUTPUT_DIR = "/home/kali/Downloads/sandbox/findings"

def decompile_function(decompiler, func):
    """Decompile a function and return the C code"""
    results = decompiler.decompileFunction(func, 60, None)
    if results and results.decompileCompleted():
        return results.getDecompiledFunction()
    return None

def save_decompilation(name, addr, c_code):
    """Save decompiled C code to file"""
    filename = "%s/decompiled_%s.c" % (OUTPUT_DIR, name)
    with open(filename, 'w') as f:
        f.write("// Function: %s @ 0x%s\n" % (name, addr))
        f.write("// File: u297528.dat (idll.dll)\n")
        f.write("// Decompilation by Ghidra\n\n")
        f.write(c_code.getC() if hasattr(c_code, 'getC') else str(c_code))
    print("Saved: %s" % filename)

# Initialize decompiler
decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

# Key functions to decompile (from previous analysis)
target_functions = {
    "IdllEntry": "0x180001820",        # Export entry point
    "DllMain": "0x180002820",          # DllMain entry
    "peb_hash_resolver": "0x180003c90", # PEB walking hash resolver
    "pe_export_resolver": "0x180003810", # PE export directory resolver
    "xor_decrypt_func": "0x180001a10", # Position-dependent XOR cipher
    "syscall_stub_1": "0x180003f30",   # Direct syscall stub 1
    "syscall_stub_2": "0x180003f3c",   # Direct syscall stub 2
    "syscall_stub_3": "0x180003f48",   # Direct syscall stub 3
    "syscall_stub_4": "0x180003f54",   # Direct syscall stub 4
    "syscall_stub_5": "0x180003f60",   # Direct syscall stub 5
    "syscall_stub_6": "0x180003f6c",   # Direct syscall stub 6
}

all_decompilations = {}

# Decompile all target functions
for name, addr_str in target_functions.items():
    addr = toAddr(addr_str)
    func = getFunctionContaining(addr)
    if func is None:
        # Try creating function if not defined
        createFunction(addr, name)
        func = getFunctionContaining(addr)
    
    if func:
        decomp_result = decompile_function(decompiler, func)
        if decomp_result:
            save_decompilation(name, addr_str, decomp_result)
            all_decompilations[name] = {
                "address": addr_str,
                "signature": str(func.getSignature()),
                "decompiled": decomp_result.getC() if hasattr(decomp_result, 'getC') else str(decomp_result)
            }
            print("Decompiled: %s @ %s" % (name, addr_str))
        else:
            print("Failed to decompile: %s @ %s" % (name, addr_str))
    else:
        print("Function not found: %s @ %s" % (name, addr_str))

# Also decompile ALL defined functions for completeness
fm = currentProgram.getFunctionManager()
all_funcs = fm.getFunctions(True)
print("\nTotal functions in program: %d" % fm.getFunctionCount())

# Save function list
func_list = []
for func in all_funcs:
    entry = func.getEntryPoint()
    sig = str(func.getSignature())
    func_list.append({"address": str(entry), "name": func.getName(), "signature": sig})

func_list_file = "%s/function_list.json" % OUTPUT_DIR
with open(func_list_file, 'w') as f:
    json.dump(func_list, f, indent=2)
print("Saved function list: %s (%d functions)" % (func_list_file, len(func_list)))

# Decompile additional functions found
extra_decomps = {}
for func_info in func_list[:50]:  # First 50 functions
    addr = toAddr(func_info["address"])
    func = getFunctionContaining(addr)
    if func and func.getName() not in target_functions:
        decomp_result = decompile_function(decompiler, func)
        if decomp_result:
            c_code = decomp_result.getC() if hasattr(decomp_result, 'getC') else str(decomp_result)
            extra_decomps[func.getName()] = {
                "address": func_info["address"],
                "decompiled": c_code
            }

# Save all decompilations as JSON
all_data = {
    "target_functions": all_decompilations,
    "extra_functions": extra_decomps,
    "function_count": fm.getFunctionCount()
}

all_decomp_file = "%s/all_decompilations.json" % OUTPUT_DIR
with open(all_decomp_file, 'w') as f:
    json.dump(all_data, f, indent=2)
print("Saved all decompilations: %s" % all_decomp_file)

# Extract data section bytes for key areas
# The .data section contains the substitution table and encrypted payload
data_section = None
blocks = currentProgram.getMemory().getBlocks()
for block in blocks:
    if block.getName() == ".data":
        data_section = block
        break

if data_section:
    print("\n.data section found:")
    print("  Start: %s" % str(data_section.getStart()))
    print("  Size: %d bytes" % data_section.getSize())
    print("  End: %s" % str(data_section.getEnd()))
    
    # Extract first 64 bytes (the substitution table header)
    start_addr = data_section.getStart()
    header_bytes = getBytes(start_addr, 64)
    header_hex = "".join("%02x" % (b & 0xff) for b in header_bytes)
    
    data_info = {
        "start": str(data_section.getStart()),
        "size": data_section.getSize(),
        "end": str(data_section.getEnd()),
        "first_64_hex": header_hex
    }
    
    data_info_file = "%s/data_section_info.json" % OUTPUT_DIR
    with open(data_info_file, 'w') as f:
        json.dump(data_info, f, indent=2)
    print("Saved data section info: %s" % data_info_file)

# Extract cross-references from IdllEntry
idll_addr = toAddr("0x180001820")
idll_func = getFunctionContaining(idll_addr)
if idll_func:
    refs = getReferencesFrom(idll_addr)
    ref_list = []
    for ref in refs:
        ref_list.append({
            "from": str(ref.getFromAddress()),
            "to": str(ref.getToAddress()),
            "type": str(ref.getReferenceType())
        })
    
    xref_file = "%s/idllentry_xrefs.json" % OUTPUT_DIR
    with open(xref_file, 'w') as f:
        json.dump(ref_list, f, indent=2)
    print("Saved IdllEntry xrefs: %s (%d refs)" % (xref_file, len(ref_list)))

decompiler.dispose()
print("\nGhidra decompile script complete!")