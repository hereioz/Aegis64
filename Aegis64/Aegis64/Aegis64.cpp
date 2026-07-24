#include <iostream>
#include <memory>
#include <LIEF/PE.hpp>
#include <capstone/capstone.h>
#include <fstream> 
#include <stdexcept>
#include <map>
#include <vector>

// Aegis64 Custom VM Opcodes
enum AegisOpcode : uint8_t {
    V_NOP = 0x00,

    V_MOVZX8 = 0x0A, V_MOVSX8 = 0x0B,
    V_MOVZX16 = 0x0C, V_MOVSX16 = 0x0D,
    V_MOVZX32 = 0x0E, V_MOVSX32 = 0x0F,

    V_PUSH_REG = 0x10, V_PUSH_IMM = 0x11, V_POP_REG = 0x12,
    V_PUSH_IMM_RVA = 0x13,

    V_READ_MEM8 = 0x14, V_WRITE_MEM8 = 0x15,
    V_READ_MEM16 = 0x16, V_WRITE_MEM16 = 0x17,

    V_READ_MEM = 0x1A, V_WRITE_MEM = 0x1B,
    V_READ_MEM32 = 0x1C, V_WRITE_MEM32 = 0x1D,

    V_ADD = 0x20, V_SUB = 0x21,
    V_XOR = 0x22, V_AND = 0x23, V_OR = 0x24, V_NOT = 0x25,
    V_MUL = 0x26, V_DIV = 0x27, V_MOD = 0x28,

    V_SHL = 0x30, V_SHR = 0x31, V_SAR = 0x32,

    V_CMP = 0x40, V_TEST = 0x41,
    V_CMP32 = 0x42, V_TEST32 = 0x43,

    V_JMP = 0x50, V_JCC = 0x51,

    V_ADD32 = 0x60, V_SUB32 = 0x61, V_XOR32 = 0x62, V_AND32 = 0x63,
    V_OR32 = 0x64, V_NOT32 = 0x65, V_IMUL32 = 0x66, V_DIV32 = 0x67,
    V_SHL32 = 0x68, V_SHR32 = 0x69, V_SAR32 = 0x6A, V_CDQ = 0x6B,

    V_CALL_EXT_IND = 0xFC,
    V_CALL_EXT = 0xFD,
    V_VMEXIT = 0xFE,
    V_EXIT = 0xFF
};

// Virtual Registers
enum AegisReg : uint8_t {
    VR_RAX = 0, VR_RCX = 1, VR_RDX = 2, VR_RBX = 3,
    VR_RSP = 4, VR_RBP = 5, VR_RSI = 6, VR_RDI = 7,
    VR_R8 = 8, VR_R9 = 9, VR_R10 = 10, VR_R11 = 11,
    VR_R12 = 12, VR_R13 = 13, VR_R14 = 14, VR_R15 = 15,
    VR_RIP = 16, VR_RFLAGS = 17
};

// Mapping Registers
uint8_t MapRegister(x86_reg capstone_reg) {
    switch (capstone_reg) {
    case X86_REG_AL:   case X86_REG_AX:   case X86_REG_EAX:   case X86_REG_RAX:   return AegisReg::VR_RAX;
    case X86_REG_CL:   case X86_REG_CX:   case X86_REG_ECX:   case X86_REG_RCX:   return AegisReg::VR_RCX;
    case X86_REG_DL:   case X86_REG_DX:   case X86_REG_EDX:   case X86_REG_RDX:   return AegisReg::VR_RDX;
    case X86_REG_BL:   case X86_REG_BX:   case X86_REG_EBX:   case X86_REG_RBX:   return AegisReg::VR_RBX;
    case X86_REG_SPL:  case X86_REG_SP:   case X86_REG_ESP:   case X86_REG_RSP:   return AegisReg::VR_RSP;
    case X86_REG_BPL:  case X86_REG_BP:   case X86_REG_EBP:   case X86_REG_RBP:   return AegisReg::VR_RBP;
    case X86_REG_SIL:  case X86_REG_SI:   case X86_REG_ESI:   case X86_REG_RSI:   return AegisReg::VR_RSI;
    case X86_REG_DIL:  case X86_REG_DI:   case X86_REG_EDI:   case X86_REG_RDI:   return AegisReg::VR_RDI;
    case X86_REG_R8B:  case X86_REG_R8W:  case X86_REG_R8D:  case X86_REG_R8:    return AegisReg::VR_R8;
    case X86_REG_R9B:  case X86_REG_R9W:  case X86_REG_R9D:  case X86_REG_R9:    return AegisReg::VR_R9;
    case X86_REG_R10B: case X86_REG_R10W: case X86_REG_R10D: case X86_REG_R10:   return AegisReg::VR_R10;
    case X86_REG_R11B: case X86_REG_R11W: case X86_REG_R11D: case X86_REG_R11:   return AegisReg::VR_R11;
    case X86_REG_R12B: case X86_REG_R12W: case X86_REG_R12D: case X86_REG_R12:   return AegisReg::VR_R12;
    case X86_REG_R13B: case X86_REG_R13W: case X86_REG_R13D: case X86_REG_R13:   return AegisReg::VR_R13;
    case X86_REG_R14B: case X86_REG_R14W: case X86_REG_R14D: case X86_REG_R14:   return AegisReg::VR_R14;
    case X86_REG_R15B: case X86_REG_R15W: case X86_REG_R15D: case X86_REG_R15:   return AegisReg::VR_R15;
    default: return 0xFF;
    }
}

struct AegisEncoder {
    // Lifted Buffer
    std::vector<uint8_t> buffer;

    // Emitting Opcode
    void EmitOpcode(AegisOpcode op) { 
        buffer.push_back(static_cast<uint8_t>(op)); 
    }

    // Emitting Register
    void EmitRegister(uint8_t reg_index) { 
        buffer.push_back(reg_index); 
    }

    // Emitting Byte
    void EmitByte(uint8_t val) { 
        buffer.push_back(val); 
    }

    // Emitting 64-bit constant in little endian
    void EmitImmediate64(uint64_t imm) {
        for (int i = 0; i < 8; ++i) 
            buffer.push_back((imm >> (i * 8)) & 0xFF);
    }
};

std::vector<uint8_t> BuildAegisSection(const std::vector<uint8_t>& vm_engine, const std::vector<uint8_t>& bytecode) {
    if (vm_engine.empty() || bytecode.empty()) {
        throw std::invalid_argument("Engine and bytecode vectors must not be empty.");
    }

    std::vector<uint8_t> combined_section;

    int32_t rip_offset = static_cast<int32_t>(vm_engine.size());

    // lea rsi, [rip + disp32]
    combined_section.push_back(0x48);
    combined_section.push_back(0x8D);
    combined_section.push_back(0x35);

    uint8_t offset_bytes[4];

    // Combining Everything Together
    std::memcpy(offset_bytes, &rip_offset, sizeof(rip_offset));

    combined_section.insert(combined_section.end(), offset_bytes, offset_bytes + 4);
    combined_section.insert(combined_section.end(), vm_engine.begin(), vm_engine.end());
    combined_section.insert(combined_section.end(), bytecode.begin(), bytecode.end());

    return combined_section;
}

bool file_exists(const std::string& name) {
    std::ifstream f(name);
    return f.good();
}

int main(int argc, char* argv[])
{
    std::cout << " - Aegis64 Virtualizer Engine - " << std::endl << std::endl;

    std::string target_file;

    // Getting file name
    if (argc > 1) {
        target_file = argv[1];
        std::cout << "Target PE specified: " << target_file << std::endl << std::endl;
    }
    else {
        std::cout << "Enter the target PE filename (e.g. dummy.exe): ";
        std::getline(std::cin, target_file);

        if (target_file.empty()) {
            std::cerr << "Error: No filename provided. Terminating.\n";
            return 1;
        }

        std::cout << "Target PE specified: " << target_file << std::endl << std::endl;
    }

    // Checking if file exists
    if (!file_exists(target_file)) {
        std::cerr << "Error: No matching file. Terminating.\n";
        return 1;
    }

    // Handling PE
    std::unique_ptr<LIEF::PE::Binary> pe;

    try {
        pe = LIEF::PE::Parser::parse(target_file);
    }
    catch (const std::exception& e) {
        std::cerr << "[-] Failed to parse PE file: " << e.what() << std::endl;
        return 1;
    }

    uint64_t begin_iat_address = 0, end_iat_address = 0;

    std::cout << "Scanning IAT..." << std::endl;

    // Finding Markers in IAT
    for (const LIEF::PE::Import& import_entry : pe->imports()) {

        if (import_entry.name() == "Aegis64SDK.dll") {

            for (const LIEF::PE::ImportEntry& func : import_entry.entries()) {

                if (func.name() == "Aegis64_Begin") 
                    begin_iat_address = func.iat_address();

                else if (func.name() == "Aegis64_End") 
                    end_iat_address = func.iat_address();

            }
        }
    }

    if (begin_iat_address == 0 || end_iat_address == 0) {
        std::cout << "Couldn't found markers..";
        return 1;
    }
    else
    {
        std::cout << "  Found Aegis64_Begin IAT RVA -> 0x" << std::hex << begin_iat_address << std::endl;
        std::cout << "  Found Aegis64_End IAT RVA -> 0x" << std::hex <<  end_iat_address << std::endl << std::endl;
    }

    // Getting VA of Markers (RVA + image base)
    uint64_t image_base = pe->optional_header().imagebase();
    uint64_t target_begin_va = image_base + begin_iat_address;
    uint64_t target_end_va = image_base + end_iat_address;

    std::cout << "Looking for CALLs to Aegis64_Begin VA: 0x" << std::hex << target_begin_va << std::endl;
    std::cout << "Looking for CALLs to Aegis64_End VA: 0x" << std::hex << target_end_va << std::endl << std::endl;

    // Getting Handle of .text
    LIEF::PE::Section* text_section = pe->get_section(".text");
    if (!text_section) {
        std::cerr << "Failed to get .text" << std::endl;
        return 1;
    }

    // 0x20000000 -> IMAGE_SCN_MEM_EXECUTE
    text_section->characteristics(text_section->characteristics() | 0x20000000);

    // Getting Content & VA of .text
    auto text_bytes = text_section->content();
    uint64_t text_start_va = image_base + text_section->virtual_address();

    // Disassembly Handle of PE
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
        std::cerr << "Failed to open handle" << std::endl;
        return 1;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    // Retrieving ASM Code
    cs_insn* insn;
    size_t count = cs_disasm(handle, text_bytes.data(), text_bytes.size(), text_start_va, 0, &insn);

    // Initializing Variables for Markers
    uint64_t vm_block_start = 0, vm_block_end = 0;
    uint16_t vm_marker_size = 0;

    // Getting Markers Locations in Code
    if (count > 0) {

        for (size_t i = 0; i < count; i++) {

            // Searching for CALL or JMP as it could be any of them (due to compilers optimizations)
            if (insn[i].id == X86_INS_CALL || insn[i].id == X86_INS_JMP) {

                cs_x86* x86 = &(insn[i].detail->x86);

                if (x86->op_count > 0 && x86->operands[0].type == X86_OP_MEM) {

                    if (x86->operands[0].mem.base == X86_REG_RIP) {

                        uint64_t call_dest = insn[i].address + insn[i].size + x86->operands[0].mem.disp;

                        if (call_dest == target_begin_va) {
                            vm_block_start = insn[i].address + insn[i].size;
                            vm_marker_size = insn[i].size;
                        }
                        else if (call_dest == target_end_va) {
                            vm_block_end = insn[i].address;
                        }
                    }
                }
            }
        }
        cs_free(insn, count);
    }
    else {
        std::cerr << "Failed to disassemble .text section" << std::endl;
        return 1;
    }


    if (!vm_block_start || !vm_block_end) {
        std::cerr << "Failed to establish valid virtualization boundaries" << std::endl;
        return 1;
    }
    else
    {
        std::cout << "Target code block successfully isolated" << std::endl;
        std::cout << "    -> Start VA: 0x" << std::hex << vm_block_start << std::endl;
        std::cout << "    -> End VA: 0x" << std::hex << vm_block_end << std::endl;
        std::cout << "    -> Total Bytes to Virtualize: " << std::dec << (vm_block_end - vm_block_start) << " bytes" << std::endl << std::endl;
    }

    // Retrieving ASM Code inside desired block to virtualize
    cs_insn* block_insn;
    size_t block_count = cs_disasm(handle, text_bytes.data() + (vm_block_start - text_start_va), vm_block_end - vm_block_start, vm_block_start, 0, &block_insn);

    // Initializing Lifter
    AegisEncoder lifter;

    // Handling execution flow
    std::map<uint64_t, size_t> instruction_map;
    std::vector<std::pair<size_t, uint64_t>> relocations;
    size_t exit_patch_offset = 0;

    auto EmitAddressCalculation = [&](cs_insn* insn, cs_x86_op* op) {
        if (op->mem.base == X86_REG_RIP) {
            uint64_t absolute_addr = insn->address + insn->size + op->mem.disp;
            uint64_t rva = absolute_addr - image_base;
            lifter.EmitOpcode(AegisOpcode::V_PUSH_IMM_RVA);
            lifter.EmitImmediate64(rva);
            return;
        }

        lifter.EmitOpcode(AegisOpcode::V_PUSH_IMM);
        lifter.EmitImmediate64(op->mem.disp);

        if (op->mem.base != X86_REG_INVALID) {
            lifter.EmitOpcode(AegisOpcode::V_PUSH_REG);
            lifter.EmitRegister(MapRegister(op->mem.base));
            lifter.EmitOpcode(AegisOpcode::V_ADD);
        }

        if (op->mem.index != X86_REG_INVALID) {
            lifter.EmitOpcode(AegisOpcode::V_PUSH_REG);
            lifter.EmitRegister(MapRegister(op->mem.index));
            if (op->mem.scale > 1) {
                lifter.EmitOpcode(AegisOpcode::V_PUSH_IMM);
                lifter.EmitImmediate64(op->mem.scale);
                lifter.EmitOpcode(AegisOpcode::V_MUL);
            }
            lifter.EmitOpcode(AegisOpcode::V_ADD);
        }
    };

    std::cout << "Starting Lifting..." << std::endl;

    // Lifting Loop
    if (block_count > 0) {
        for (size_t i = 0; i < block_count; i++) {

            instruction_map[block_insn[i].address] = lifter.buffer.size();
            cs_x86* x86 = &(block_insn[i].detail->x86);

            switch (block_insn[i].id) {

            case X86_INS_CDQ: {
                lifter.EmitOpcode(AegisOpcode::V_CDQ);
                break;
            }

            case X86_INS_PUSH: {
                cs_x86_op* op = &x86->operands[0];
                if (op->type == X86_OP_REG) {
                    uint8_t v_target = MapRegister(op->reg);
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_REG);
                    lifter.EmitRegister(AegisReg::VR_RSP);
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_IMM);
                    lifter.EmitImmediate64(8);
                    lifter.EmitOpcode(AegisOpcode::V_SUB);
                    lifter.EmitOpcode(AegisOpcode::V_POP_REG);
                    lifter.EmitRegister(AegisReg::VR_RSP);

                    lifter.EmitOpcode(AegisOpcode::V_PUSH_REG);
                    lifter.EmitRegister(v_target);
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_REG);
                    lifter.EmitRegister(AegisReg::VR_RSP);
                    lifter.EmitOpcode(AegisOpcode::V_WRITE_MEM);
                }
                else if (op->type == X86_OP_IMM) {
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_REG);
                    lifter.EmitRegister(AegisReg::VR_RSP);
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_IMM);
                    lifter.EmitImmediate64(8);
                    lifter.EmitOpcode(AegisOpcode::V_SUB);
                    lifter.EmitOpcode(AegisOpcode::V_POP_REG);
                    lifter.EmitRegister(AegisReg::VR_RSP);

                    lifter.EmitOpcode(AegisOpcode::V_PUSH_IMM);
                    lifter.EmitImmediate64(op->imm);
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_REG);
                    lifter.EmitRegister(AegisReg::VR_RSP);
                    lifter.EmitOpcode(AegisOpcode::V_WRITE_MEM);
                }
                break;
            }

            case X86_INS_POP: {
                cs_x86_op* op = &x86->operands[0];
                if (op->type == X86_OP_REG) {
                    uint8_t v_target = MapRegister(op->reg);
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_REG);
                    lifter.EmitRegister(AegisReg::VR_RSP);
                    lifter.EmitOpcode(AegisOpcode::V_READ_MEM);
                    lifter.EmitOpcode(AegisOpcode::V_POP_REG);
                    lifter.EmitRegister(v_target);

                    lifter.EmitOpcode(AegisOpcode::V_PUSH_REG);
                    lifter.EmitRegister(AegisReg::VR_RSP);
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_IMM);
                    lifter.EmitImmediate64(8);
                    lifter.EmitOpcode(AegisOpcode::V_ADD);
                    lifter.EmitOpcode(AegisOpcode::V_POP_REG);
                    lifter.EmitRegister(AegisReg::VR_RSP);
                }
                break;
            }

            case X86_INS_MOV: {
                cs_x86_op* dest = &x86->operands[0];
                cs_x86_op* src = &x86->operands[1];

                // FORCE FALLBACK: Protect Partial Registers from VM Corruption
                if (dest->size < 4 || src->size < 4) {
                    lifter.EmitOpcode(AegisOpcode::V_VMEXIT);
                    lifter.EmitByte(block_insn[i].size);
                    for (int j = 0; j < block_insn[i].size; j++) lifter.EmitByte(block_insn[i].bytes[j]);
                    break;
                }

                if (dest->type == X86_OP_REG && src->type == X86_OP_IMM) {
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_IMM);
                    lifter.EmitImmediate64(src->imm);
                    if (dest->size == 4) lifter.EmitOpcode(AegisOpcode::V_MOVZX32);
                    lifter.EmitOpcode(AegisOpcode::V_POP_REG);
                    lifter.EmitRegister(MapRegister(dest->reg));
                }
                else if (dest->type == X86_OP_REG && src->type == X86_OP_REG) {
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_REG);
                    lifter.EmitRegister(MapRegister(src->reg));
                    if (dest->size == 4) lifter.EmitOpcode(AegisOpcode::V_MOVZX32);
                    lifter.EmitOpcode(AegisOpcode::V_POP_REG);
                    lifter.EmitRegister(MapRegister(dest->reg));
                }
                else if (dest->type == X86_OP_REG && src->type == X86_OP_MEM) {
                    EmitAddressCalculation(&block_insn[i], src);
                    if (src->size == 4) lifter.EmitOpcode(AegisOpcode::V_READ_MEM32);
                    else lifter.EmitOpcode(AegisOpcode::V_READ_MEM);

                    lifter.EmitOpcode(AegisOpcode::V_POP_REG);
                    lifter.EmitRegister(MapRegister(dest->reg));
                }
                else if (dest->type == X86_OP_MEM && src->type == X86_OP_REG) {
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_REG);
                    lifter.EmitRegister(MapRegister(src->reg));
                    EmitAddressCalculation(&block_insn[i], dest);

                    if (dest->size == 4) lifter.EmitOpcode(AegisOpcode::V_WRITE_MEM32);
                    else lifter.EmitOpcode(AegisOpcode::V_WRITE_MEM);
                }
                else if (dest->type == X86_OP_MEM && src->type == X86_OP_IMM) {
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_IMM);
                    lifter.EmitImmediate64(src->imm);
                    EmitAddressCalculation(&block_insn[i], dest);

                    if (dest->size == 4) lifter.EmitOpcode(AegisOpcode::V_WRITE_MEM32);
                    else lifter.EmitOpcode(AegisOpcode::V_WRITE_MEM);
                }
                break;
            }

            case X86_INS_IMUL:
            case X86_INS_XOR:
            case X86_INS_AND:
            case X86_INS_OR:
            case X86_INS_ADD:
            case X86_INS_SUB: {
                cs_x86_op* dest = &x86->operands[0];
                cs_x86_op* src = &x86->operands[1];

                // FORCE FALLBACK: Isolate 8/16-bit math native flag semantics and partial reg updates
                if (x86->op_count != 2 || dest->size < 4) {
                    lifter.EmitOpcode(AegisOpcode::V_VMEXIT);
                    lifter.EmitByte(block_insn[i].size);
                    for (int j = 0; j < block_insn[i].size; j++) lifter.EmitByte(block_insn[i].bytes[j]);
                    break;
                }

                if (dest->type == X86_OP_REG) {
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_REG);
                    lifter.EmitRegister(MapRegister(dest->reg));
                }
                else if (dest->type == X86_OP_MEM) {
                    EmitAddressCalculation(&block_insn[i], dest);
                    if (dest->size == 4) lifter.EmitOpcode(AegisOpcode::V_READ_MEM32);
                    else lifter.EmitOpcode(AegisOpcode::V_READ_MEM);
                }

                if (src->type == X86_OP_IMM) {
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_IMM);
                    lifter.EmitImmediate64(src->imm);
                }
                else if (src->type == X86_OP_REG) {
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_REG);
                    lifter.EmitRegister(MapRegister(src->reg));
                }
                else if (src->type == X86_OP_MEM) {
                    EmitAddressCalculation(&block_insn[i], src);
                    if (src->size == 4) lifter.EmitOpcode(AegisOpcode::V_READ_MEM32);
                    else lifter.EmitOpcode(AegisOpcode::V_READ_MEM);
                }

                uint8_t op_size = dest->size;
                switch (block_insn[i].id) {
                case X86_INS_XOR:  lifter.EmitOpcode(op_size == 4 ? AegisOpcode::V_XOR32 : AegisOpcode::V_XOR); break;
                case X86_INS_AND:  lifter.EmitOpcode(op_size == 4 ? AegisOpcode::V_AND32 : AegisOpcode::V_AND); break;
                case X86_INS_OR:   lifter.EmitOpcode(op_size == 4 ? AegisOpcode::V_OR32 : AegisOpcode::V_OR); break;
                case X86_INS_ADD:  lifter.EmitOpcode(op_size == 4 ? AegisOpcode::V_ADD32 : AegisOpcode::V_ADD); break;
                case X86_INS_SUB:  lifter.EmitOpcode(op_size == 4 ? AegisOpcode::V_SUB32 : AegisOpcode::V_SUB); break;
                case X86_INS_IMUL: lifter.EmitOpcode(op_size == 4 ? AegisOpcode::V_IMUL32 : AegisOpcode::V_MUL); break;
                }

                if (dest->type == X86_OP_MEM) {
                    EmitAddressCalculation(&block_insn[i], dest);
                    if (dest->size == 4) lifter.EmitOpcode(AegisOpcode::V_WRITE_MEM32);
                    else lifter.EmitOpcode(AegisOpcode::V_WRITE_MEM);
                }
                else if (dest->type == X86_OP_REG) {
                    lifter.EmitOpcode(AegisOpcode::V_POP_REG);
                    lifter.EmitRegister(MapRegister(dest->reg));
                }
                break;
            }

            case X86_INS_INC:
            case X86_INS_DEC: {
                cs_x86_op* op = &x86->operands[0];
                if (op->type == X86_OP_REG && op->size >= 4) {
                    uint8_t v_dest = MapRegister(op->reg);
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_REG);
                    lifter.EmitRegister(v_dest);
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_IMM);
                    lifter.EmitImmediate64(1);

                    if (block_insn[i].id == X86_INS_INC) lifter.EmitOpcode(op->size == 4 ? AegisOpcode::V_ADD32 : AegisOpcode::V_ADD);
                    else lifter.EmitOpcode(op->size == 4 ? AegisOpcode::V_SUB32 : AegisOpcode::V_SUB);

                    lifter.EmitOpcode(AegisOpcode::V_POP_REG);
                    lifter.EmitRegister(v_dest);
                }
                else {
                    lifter.EmitOpcode(AegisOpcode::V_VMEXIT);
                    lifter.EmitByte(block_insn[i].size);
                    for (int j = 0; j < block_insn[i].size; j++) lifter.EmitByte(block_insn[i].bytes[j]);
                }
                break;
            }

            case X86_INS_NOT: {
                cs_x86_op* dest = &x86->operands[0];
                if (dest->type == X86_OP_REG && dest->size >= 4) {
                    uint8_t v_dest = MapRegister(dest->reg);
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_REG);
                    lifter.EmitRegister(v_dest);
                    lifter.EmitOpcode(dest->size == 4 ? AegisOpcode::V_NOT32 : AegisOpcode::V_NOT);
                    lifter.EmitOpcode(AegisOpcode::V_POP_REG);
                    lifter.EmitRegister(v_dest);
                }
                else {
                    lifter.EmitOpcode(AegisOpcode::V_VMEXIT);
                    lifter.EmitByte(block_insn[i].size);
                    for (int j = 0; j < block_insn[i].size; j++) lifter.EmitByte(block_insn[i].bytes[j]);
                }
                break;
            }

            case X86_INS_SHL: case X86_INS_SHR: case X86_INS_SAR: {
                cs_x86_op* dest = &x86->operands[0];
                cs_x86_op* src = &x86->operands[1];

                if (dest->type == X86_OP_REG && dest->size >= 4) {
                    uint8_t v_dest = MapRegister(dest->reg);
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_REG);
                    lifter.EmitRegister(v_dest);

                    if (src->type == X86_OP_IMM) {
                        lifter.EmitOpcode(AegisOpcode::V_PUSH_IMM);
                        lifter.EmitImmediate64(src->imm);
                    }
                    else if (src->type == X86_OP_REG) {
                        lifter.EmitOpcode(AegisOpcode::V_PUSH_REG);
                        lifter.EmitRegister(MapRegister(src->reg));
                    }

                    switch (block_insn[i].id) {
                    case X86_INS_SHL: lifter.EmitOpcode(dest->size == 4 ? AegisOpcode::V_SHL32 : AegisOpcode::V_SHL); break;
                    case X86_INS_SHR: lifter.EmitOpcode(dest->size == 4 ? AegisOpcode::V_SHR32 : AegisOpcode::V_SHR); break;
                    case X86_INS_SAR: lifter.EmitOpcode(dest->size == 4 ? AegisOpcode::V_SAR32 : AegisOpcode::V_SAR); break;
                    }

                    lifter.EmitOpcode(AegisOpcode::V_POP_REG);
                    lifter.EmitRegister(v_dest);
                }
                else {
                    lifter.EmitOpcode(AegisOpcode::V_VMEXIT);
                    lifter.EmitByte(block_insn[i].size);
                    for (int j = 0; j < block_insn[i].size; j++) lifter.EmitByte(block_insn[i].bytes[j]);
                }
                break;
            }

            case X86_INS_LEA: {
                cs_x86_op* dest = &x86->operands[0];
                cs_x86_op* src = &x86->operands[1];

                if (dest->type == X86_OP_REG && src->type == X86_OP_MEM) {
                    EmitAddressCalculation(&block_insn[i], src);
                    if (dest->size == 4) lifter.EmitOpcode(AegisOpcode::V_MOVZX32);
                    lifter.EmitOpcode(AegisOpcode::V_POP_REG);
                    lifter.EmitRegister(MapRegister(dest->reg));
                }
                break;
            }

            case X86_INS_MUL: {
                cs_x86_op* src = &x86->operands[0];
                if (src->type == X86_OP_REG && src->size >= 4) {
                    uint8_t v_src = MapRegister(src->reg);
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_REG);
                    lifter.EmitRegister(AegisReg::VR_RAX);
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_REG);
                    lifter.EmitRegister(v_src);
                    lifter.EmitOpcode(AegisOpcode::V_MUL);
                    lifter.EmitOpcode(AegisOpcode::V_POP_REG);
                    lifter.EmitRegister(AegisReg::VR_RAX);
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_IMM);
                    lifter.EmitImmediate64(0);
                    lifter.EmitOpcode(AegisOpcode::V_POP_REG);
                    lifter.EmitRegister(AegisReg::VR_RDX);
                }
                else {
                    lifter.EmitOpcode(AegisOpcode::V_VMEXIT);
                    lifter.EmitByte(block_insn[i].size);
                    for (int j = 0; j < block_insn[i].size; j++) lifter.EmitByte(block_insn[i].bytes[j]);
                }
                break;
            }

            case X86_INS_DIV: {
                cs_x86_op* src = &x86->operands[0];
                if (src->type == X86_OP_REG && src->size >= 4) {
                    uint8_t v_src = MapRegister(src->reg);
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_REG);
                    lifter.EmitRegister(AegisReg::VR_RAX);
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_REG);
                    lifter.EmitRegister(v_src);
                    lifter.EmitOpcode(src->size == 4 ? AegisOpcode::V_DIV32 : AegisOpcode::V_DIV);
                    lifter.EmitOpcode(AegisOpcode::V_POP_REG);
                    lifter.EmitRegister(AegisReg::VR_RAX);
                }
                else {
                    lifter.EmitOpcode(AegisOpcode::V_VMEXIT);
                    lifter.EmitByte(block_insn[i].size);
                    for (int j = 0; j < block_insn[i].size; j++) lifter.EmitByte(block_insn[i].bytes[j]);
                }
                break;
            }

            case X86_INS_CMP:
            case X86_INS_TEST: {
                cs_x86_op* dest = &x86->operands[0];
                cs_x86_op* src = &x86->operands[1];

                if (dest->size < 4) {
                    lifter.EmitOpcode(AegisOpcode::V_VMEXIT);
                    lifter.EmitByte(block_insn[i].size);
                    for (int j = 0; j < block_insn[i].size; j++) lifter.EmitByte(block_insn[i].bytes[j]);
                    break;
                }

                if (dest->type == X86_OP_REG) {
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_REG);
                    lifter.EmitRegister(MapRegister(dest->reg));
                }
                else if (dest->type == X86_OP_MEM) {
                    EmitAddressCalculation(&block_insn[i], dest);
                    if (dest->size == 4) lifter.EmitOpcode(AegisOpcode::V_READ_MEM32);
                    else lifter.EmitOpcode(AegisOpcode::V_READ_MEM);
                }

                if (src->type == X86_OP_IMM) {
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_IMM);
                    lifter.EmitImmediate64(src->imm);
                }
                else if (src->type == X86_OP_REG) {
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_REG);
                    lifter.EmitRegister(MapRegister(src->reg));
                }

                if (block_insn[i].id == X86_INS_CMP) {
                    lifter.EmitOpcode(dest->size == 4 ? AegisOpcode::V_CMP32 : AegisOpcode::V_CMP);
                }
                else {
                    lifter.EmitOpcode(dest->size == 4 ? AegisOpcode::V_TEST32 : AegisOpcode::V_TEST);
                }
                break;
            }

            case X86_INS_CALL: {
                cs_x86_op* dest = &x86->operands[0];
                if (dest->type == X86_OP_MEM && dest->mem.base == X86_REG_RIP) {
                    uint64_t absolute_target = block_insn[i].address + block_insn[i].size + dest->mem.disp;
                    uint64_t rva = absolute_target - image_base;
                    lifter.EmitOpcode(AegisOpcode::V_CALL_EXT_IND);
                    lifter.EmitImmediate64(rva);
                }
                else if (dest->type == X86_OP_IMM) {
                    uint64_t rva = dest->imm - image_base;
                    lifter.EmitOpcode(AegisOpcode::V_CALL_EXT);
                    lifter.EmitImmediate64(rva);
                }
                break;
            }

            case X86_INS_MOVZX:
            case X86_INS_MOVSX: {
                cs_x86_op* dest = &x86->operands[0];
                cs_x86_op* src = &x86->operands[1];

                if (src->type == X86_OP_MEM) {
                    EmitAddressCalculation(&block_insn[i], src);
                    if (src->size == 1) lifter.EmitOpcode(AegisOpcode::V_READ_MEM8);
                    else if (src->size == 2) lifter.EmitOpcode(AegisOpcode::V_READ_MEM16);
                    else if (src->size == 4) lifter.EmitOpcode(AegisOpcode::V_READ_MEM32);
                    else lifter.EmitOpcode(AegisOpcode::V_READ_MEM);
                }
                else if (src->type == X86_OP_REG) {
                    lifter.EmitOpcode(AegisOpcode::V_PUSH_REG);
                    lifter.EmitRegister(MapRegister(src->reg));
                }

                if (block_insn[i].id == X86_INS_MOVZX) {
                    if (src->size == 1) lifter.EmitOpcode(AegisOpcode::V_MOVZX8);
                    else if (src->size == 2) lifter.EmitOpcode(AegisOpcode::V_MOVZX16);
                    else if (src->size == 4) lifter.EmitOpcode(AegisOpcode::V_MOVZX32);
                }
                else {
                    if (src->size == 1) lifter.EmitOpcode(AegisOpcode::V_MOVSX8);
                    else if (src->size == 2) lifter.EmitOpcode(AegisOpcode::V_MOVSX16);
                    else if (src->size == 4) lifter.EmitOpcode(AegisOpcode::V_MOVSX32);
                }

                if (dest->type == X86_OP_REG) {
                    lifter.EmitOpcode(AegisOpcode::V_POP_REG);
                    lifter.EmitRegister(MapRegister(dest->reg));
                }
                break;
            }

            case X86_INS_JMP:
            case X86_INS_JE:  case X86_INS_JNE:
            case X86_INS_JG:  case X86_INS_JGE:
            case X86_INS_JL:  case X86_INS_JLE:
            case X86_INS_JA:  case X86_INS_JAE:
            case X86_INS_JB:  case X86_INS_JBE:
            case X86_INS_JS:  case X86_INS_JNS:
            case X86_INS_JP:  case X86_INS_JNP:
            case X86_INS_JO:  case X86_INS_JNO: {
                cs_x86_op* dest = &x86->operands[0];

                if (dest->type == X86_OP_IMM) {
                    uint64_t target_addr = dest->imm;
                    if (target_addr >= vm_block_start && target_addr < vm_block_end) {
                        if (block_insn[i].id == X86_INS_JMP) {
                            lifter.EmitOpcode(AegisOpcode::V_JMP);
                        }
                        else {
                            uint8_t normalized_jcc = 0xFF;
                            switch (block_insn[i].id) {
                            case X86_INS_JE:  normalized_jcc = 0x00; break;
                            case X86_INS_JNE: normalized_jcc = 0x01; break;
                            case X86_INS_JA:  normalized_jcc = 0x02; break;
                            case X86_INS_JAE: normalized_jcc = 0x03; break;
                            case X86_INS_JB:  normalized_jcc = 0x04; break;
                            case X86_INS_JBE: normalized_jcc = 0x05; break;
                            case X86_INS_JG:  normalized_jcc = 0x06; break;
                            case X86_INS_JGE: normalized_jcc = 0x07; break;
                            case X86_INS_JL:  normalized_jcc = 0x08; break;
                            case X86_INS_JLE: normalized_jcc = 0x09; break;
                            case X86_INS_JS:  normalized_jcc = 0x0A; break;
                            case X86_INS_JNS: normalized_jcc = 0x0B; break;
                            case X86_INS_JP:  normalized_jcc = 0x0C; break;
                            case X86_INS_JNP: normalized_jcc = 0x0D; break;
                            case X86_INS_JO:  normalized_jcc = 0x0E; break;
                            case X86_INS_JNO: normalized_jcc = 0x0F; break;
                            }
                            lifter.EmitOpcode(AegisOpcode::V_JCC);
                            lifter.EmitByte(normalized_jcc);
                        }

                        relocations.push_back({ lifter.buffer.size(), target_addr });
                        lifter.EmitImmediate64(0);
                    }
                    else {
                        uint64_t escape_rva = target_addr - image_base;
                        lifter.EmitOpcode(AegisOpcode::V_EXIT);
                        lifter.EmitImmediate64(escape_rva);
                    }
                }
                else if (dest->type == X86_OP_REG || dest->type == X86_OP_MEM) {
                    lifter.EmitOpcode(AegisOpcode::V_VMEXIT);
                    lifter.EmitByte(block_insn[i].size);
                    for (int j = 0; j < block_insn[i].size; j++) lifter.EmitByte(block_insn[i].bytes[j]);
                }
                break;
            }

            default:
                lifter.EmitOpcode(AegisOpcode::V_VMEXIT);
                lifter.EmitByte(block_insn[i].size);
                for (int j = 0; j < block_insn[i].size; j++) lifter.EmitByte(block_insn[i].bytes[j]);
                break;
            }
        }

        lifter.EmitOpcode(AegisOpcode::V_EXIT);
        exit_patch_offset = lifter.buffer.size();
        lifter.EmitImmediate64(0);
        cs_free(block_insn, block_count);
    }

    std::cout << "All instructions lifted successfully" << std::endl << std::endl;

    // Handling bin file
    std::ifstream engine_file("aegis_vm.bin", std::ios::binary | std::ios::ate);
    if (!engine_file) {
        std::cerr << "Couldn't find aegis_vm.bin" << std::endl;
        return 1;
    }

    std::streamsize size = engine_file.tellg();
    engine_file.seekg(0, std::ios::beg);
    std::vector<uint8_t> nasm_engine(size);

    if (!engine_file.read(reinterpret_cast<char*>(nasm_engine.data()), size)) {
        std::cerr << "Couldn't read aegis_vm.bin" << std::endl;
        return 1;
    }

    std::cout << "Setting up Bytecode and VM..." << std::endl;

    // Building Final Payload
    std::vector<uint8_t> final_payload;
    try {
        final_payload = BuildAegisSection(nasm_engine, lifter.buffer);
    }
    catch (const std::exception& e) { 
        std::cerr << "Couldn't Setting up Bytecode and VM" << std::endl;
        return 1; 
    }

    std::cout << "Creating .aegis section..." << std::endl;

    // Adding new VM section
    LIEF::PE::Section aegis_section(".aegis");
    aegis_section.content(final_payload);

    // 0xE0000020 -> IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE
    aegis_section.characteristics(0xE0000020);

    // Adding Section & Getting VA
    LIEF::PE::Section* added_section = pe->add_section(aegis_section);
    uint64_t new_section_va = pe->optional_header().imagebase() + added_section->virtual_address();

    // Handling every branch, jump, or call that was left unresolved
    for (const auto& reloc : relocations) {
        size_t target_offset = instruction_map[reloc.second];
        size_t patch_index = 7 + nasm_engine.size() + reloc.first;

        std::memcpy(&final_payload[patch_index], &target_offset, 8);
    }

    uint64_t exit_rva = vm_block_end - image_base;
    size_t exit_patch_index = 7 + nasm_engine.size() + exit_patch_offset;
    std::memcpy(&final_payload[exit_patch_index], &exit_rva, 8);

    std::cout << "Adding VM and Bytecode to .aegis..." << std::endl << std::endl;

    // Adding Final Payload to the new section
    added_section->content(final_payload);

    // Adding the jmp to the VM
    std::vector<uint8_t> hijack_payload(vm_block_end - vm_block_start, 0x90);
    hijack_payload[0] = 0xE9;
    int32_t relative_offset = static_cast<int32_t>(new_section_va - (vm_block_start + 5));
    hijack_payload[1] = (relative_offset >> 0) & 0xFF;
    hijack_payload[2] = (relative_offset >> 8) & 0xFF;
    hijack_payload[3] = (relative_offset >> 16) & 0xFF;
    hijack_payload[4] = (relative_offset >> 24) & 0xFF;

    std::cout << "Removing non virtualized code & Markers..." << std::endl;

    // Deleting non virtualized code
    uint64_t block_rva = vm_block_start - pe->optional_header().imagebase();
    pe->patch_address(block_rva, hijack_payload);

    // Deleting Markers
    std::vector<uint8_t> nop_call(vm_marker_size, 0x90);
    pe->patch_address(vm_block_start - vm_marker_size, nop_call);
    pe->patch_address(vm_block_end, nop_call);


    std::cout << "Removing Aegis64SDK.dll..." << std::endl << std::endl;

    // Deleting Aegis64SDK.dll from IAT
    pe->remove_import("Aegis64SDK.dll");

    // Force IAT to be updated
    LIEF::PE::Builder::config_t config;
    config.imports = true;

    // Writing the new protected PE
    pe->write(target_file + "_protected.exe", config);

    std::cout << "Protected file (" << target_file + "_protected.exe" << ") generated successfully" << std::endl;

    // Closing Handle
    cs_close(&handle);
    return 0;
}