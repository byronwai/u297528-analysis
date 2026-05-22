// Ghidra Java headless decompile script for u297528.dat (idll.dll)
// @category Analysis

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import java.io.FileWriter;
import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;

public class DecompileIdllEntry extends GhidraScript {

    String OUTPUT_DIR = "/home/kali/Downloads/sandbox/findings";

    @Override
    public void run() throws Exception {
        println("Starting decompile script...");

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        // Key functions to decompile
        String[][] targets = {
            {"IdllEntry", "0x180001820"},
            {"DllMain", "0x180002820"},
            {"peb_hash_resolver", "0x180003c90"},
            {"pe_export_resolver", "0x180003810"},
            {"xor_decrypt_func", "0x180001a10"},
            {"init_func", "0x180001000"},
            {"syscall_stub_1", "0x180003f30"},
            {"syscall_stub_2", "0x180003f3c"},
            {"syscall_stub_3", "0x180003f48"},
            {"syscall_stub_4", "0x180003f54"},
            {"syscall_stub_5", "0x180003f60"},
            {"syscall_stub_6", "0x180003f6c"},
        };

        // Save each decompilation
        for (String[] target : targets) {
            String name = target[0];
            String addrStr = target[1];
            Address addr = toAddr(addrStr);
            Function func = getFunctionContaining(addr);

            if (func == null) {
                // Try creating the function
                try {
                    createFunction(addr, name);
                    func = getFunctionContaining(addr);
                } catch (Exception e) {
                    println("Could not create function: " + name + " @ " + addrStr);
                }
            }

            if (func != null) {
                DecompileResults results = decompiler.decompileFunction(func, 60, monitor);
                if (results != null && results.decompileCompleted()) {
                    String cCode = results.getDecompiledFunction().getC();
                    
                    // Save to file
                    String filename = OUTPUT_DIR + "/decompiled_" + name + ".c";
                    FileWriter fw = new FileWriter(filename);
                    fw.write("// Function: " + name + " @ " + addrStr + "\n");
                    fw.write("// File: u297528.dat (idll.dll)\n");
                    fw.write("// Decompilation by Ghidra\n\n");
                    fw.write(cCode);
                    fw.close();
                    println("Decompiled: " + name + " @ " + addrStr + " -> " + filename);
                } else {
                    println("Failed to decompile: " + name + " @ " + addrStr);
                }
            } else {
                println("Function not found: " + name + " @ " + addrStr);
            }
        }

        // Save function list
        FunctionManager fm = currentProgram.getFunctionManager();
        ArrayList<String> funcList = new ArrayList<>();
        for (Function func : fm.getFunctions(true)) {
            funcList.add(func.getEntryPoint() + " " + func.getName() + " " + func.getSignature());
        }
        
        String funcListFile = OUTPUT_DIR + "/function_list.txt";
        FileWriter fw2 = new FileWriter(funcListFile);
        fw2.write("Total functions: " + fm.getFunctionCount() + "\n\n");
        for (String entry : funcList) {
            fw2.write(entry + "\n");
        }
        fw2.close();
        println("Saved function list: " + funcListFile + " (" + fm.getFunctionCount() + " functions)");

        // Extract .data section info
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (block.getName().equals(".data")) {
                println(".data section: Start=" + block.getStart() + " Size=" + block.getSize() + " End=" + block.getEnd());
                
                // Read first 256 bytes
                byte[] header = new byte[256];
                block.getBytes(block.getStart(), header);
                
                StringBuilder hex = new StringBuilder();
                for (byte b : header) {
                    hex.append(String.format("%02x", b & 0xff));
                }
                
                String dataInfoFile = OUTPUT_DIR + "/data_section_header_hex.txt";
                FileWriter fw3 = new FileWriter(dataInfoFile);
                fw3.write("Start: " + block.getStart() + "\n");
                fw3.write("Size: " + block.getSize() + "\n");
                fw3.write("End: " + block.getEnd() + "\n\n");
                fw3.write("First 256 bytes (hex):\n");
                fw3.write(hex.toString() + "\n");
                fw3.close();
                println("Saved .data section header: " + dataInfoFile);
                
                // Read the region around offset 0x57d000 (payload boundary)
                Address payloadStart = block.getStart().add(0x57d000);
                if (payloadStart.compareTo(block.getEnd()) < 0) {
                    byte[] payloadHeader = new byte[256];
                    try {
                        block.getBytes(payloadStart, payloadHeader);
                        StringBuilder payloadHex = new StringBuilder();
                        for (byte b : payloadHeader) {
                            payloadHex.append(String.format("%02x", b & 0xff));
                        }
                        String payloadFile = OUTPUT_DIR + "/payload_start_hex.txt";
                        FileWriter fw4 = new FileWriter(payloadFile);
                        fw4.write("Payload start address: " + payloadStart + "\n");
                        fw4.write("First 256 bytes (hex):\n");
                        fw4.write(payloadHex.toString() + "\n");
                        fw4.close();
                        println("Saved payload start: " + payloadFile);
                    } catch (Exception e) {
                        println("Could not read payload region: " + e.getMessage());
                    }
                }
                
                // Also read the key byte storage area at 0x180c51530
                Address keyAddr = toAddr("0x180c51530");
                byte[] keyBytes = new byte[32];
                try {
                    getBytes(keyAddr, keyBytes);
                    StringBuilder keyHex = new StringBuilder();
                    for (byte b : keyBytes) {
                        keyHex.append(String.format("%02x", b & 0xff));
                    }
                    String keyFile = OUTPUT_DIR + "/syscall_number_storage_hex.txt";
                    FileWriter fw5 = new FileWriter(keyFile);
                    fw5.write("Syscall number storage @ 0x180c51530 (32 bytes):\n");
                    fw5.write(keyHex.toString() + "\n");
                    fw5.close();
                    println("Saved syscall storage: " + keyFile);
                } catch (Exception e) {
                    println("Could not read syscall storage: " + e.getMessage());
                }
                break;
            }
        }

        // Extract cross-references from IdllEntry
        Address idllAddr = toAddr("0x180001820");
        Function idllFunc = getFunctionContaining(idllAddr);
        if (idllFunc != null) {
            StringBuilder xrefBuilder = new StringBuilder();
            xrefBuilder.append("IdllEntry cross-references:\n\n");
            
            // Get calls FROM IdllEntry
            Address[] callsFrom = idllFunc.getCalledFunctions(monitor);
            xrefBuilder.append("Functions called by IdllEntry:\n");
            for (Address callAddr : callsFrom) {
                Function called = getFunctionContaining(callAddr);
                if (called != null) {
                    xrefBuilder.append("  -> " + called.getEntryPoint() + " " + called.getName() + "\n");
                }
            }
            
            // Get references TO IdllEntry
            xrefBuilder.append("\nReferences to IdllEntry:\n");
            ghidra.program.model.symbol.Reference[] refs = getReferencesTo(idllAddr);
            for (ghidra.program.model.symbol.Reference ref : refs) {
                xrefBuilder.append("  " + ref.getFromAddress() + " -> " + ref.getToAddress() + " (" + ref.getReferenceType() + ")\n");
            }
            
            String xrefFile = OUTPUT_DIR + "/idllentry_xrefs.txt";
            FileWriter fw6 = new FileWriter(xrefFile);
            fw6.write(xrefBuilder.toString());
            fw6.close();
            println("Saved IdllEntry xrefs: " + xrefFile);
        }

        decompiler.dispose();
        println("Ghidra decompile script complete!");
    }
}