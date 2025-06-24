module;

#include <cstdint>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

#include <Zydis/Zydis.h>

export module zydis:assembler;

import :decoder;

export namespace zydis::assembler {
    struct instruction;
    class code_block;

    struct reg {
        ZydisRegister value;
    };

    struct imm {
        ZyanI64 value;

        template <std::integral T>
        imm(T val) : value(static_cast<ZyanI64>(val)) {
        }
    };

    struct mem {
        ZydisRegister base{ZYDIS_REGISTER_NONE};
        ZydisRegister index{ZYDIS_REGISTER_NONE};
        ZyanU8 scale{1};
        ZyanI64 disp{0};
        ZyanU16 size_override{0};
    };

    using operand = std::variant<reg, imm, mem>;

    // GPRs
    namespace registers {
        // clang-format off
        // 8-bit
        constexpr reg al{ZYDIS_REGISTER_AL};
        constexpr reg cl{ZYDIS_REGISTER_CL};
        constexpr reg dl{ZYDIS_REGISTER_DL};
        constexpr reg bl{ZYDIS_REGISTER_BL};

        constexpr reg ah{ZYDIS_REGISTER_AH};
        constexpr reg ch{ZYDIS_REGISTER_CH};
        constexpr reg dh{ZYDIS_REGISTER_DH};
        constexpr reg bh{ZYDIS_REGISTER_BH};

        constexpr reg spl{ZYDIS_REGISTER_SPL};
        constexpr reg bpl{ZYDIS_REGISTER_BPL};
        constexpr reg sil{ZYDIS_REGISTER_SIL};
        constexpr reg dil{ZYDIS_REGISTER_DIL};

        constexpr reg r8b{ZYDIS_REGISTER_R8B};
        constexpr reg r9b{ZYDIS_REGISTER_R9B};
        constexpr reg r10b{ZYDIS_REGISTER_R10B};
        constexpr reg r11b{ZYDIS_REGISTER_R11B};
        constexpr reg r12b{ZYDIS_REGISTER_R12B};
        constexpr reg r13b{ZYDIS_REGISTER_R13B};
        constexpr reg r14b{ZYDIS_REGISTER_R14B};
        constexpr reg r15b{ZYDIS_REGISTER_R15B};

        // 16-bit
        constexpr reg ax{ZYDIS_REGISTER_AX};
        constexpr reg cx{ZYDIS_REGISTER_CX};
        constexpr reg dx{ZYDIS_REGISTER_DX};
        constexpr reg bx{ZYDIS_REGISTER_BX};

        constexpr reg sp{ZYDIS_REGISTER_SP};
        constexpr reg bp{ZYDIS_REGISTER_BP};
        constexpr reg si{ZYDIS_REGISTER_SI};
        constexpr reg di{ZYDIS_REGISTER_DI};

        constexpr reg r8w{ZYDIS_REGISTER_R8W};
        constexpr reg r9w{ZYDIS_REGISTER_R9W};
        constexpr reg r10w{ZYDIS_REGISTER_R10W};
        constexpr reg r11w{ZYDIS_REGISTER_R11W};
        constexpr reg r12w{ZYDIS_REGISTER_R12W};
        constexpr reg r13w{ZYDIS_REGISTER_R13W};
        constexpr reg r14w{ZYDIS_REGISTER_R14W};
        constexpr reg r15w{ZYDIS_REGISTER_R15W};

        // 32-bit
        constexpr reg eax{ZYDIS_REGISTER_EAX};
        constexpr reg ecx{ZYDIS_REGISTER_ECX};
        constexpr reg edx{ZYDIS_REGISTER_EDX};
        constexpr reg ebx{ZYDIS_REGISTER_EBX};

        constexpr reg esp{ZYDIS_REGISTER_ESP};
        constexpr reg ebp{ZYDIS_REGISTER_EBP};
        constexpr reg esi{ZYDIS_REGISTER_ESI};
        constexpr reg edi{ZYDIS_REGISTER_EDI};

        constexpr reg r8d{ZYDIS_REGISTER_R8D};
        constexpr reg r9d{ZYDIS_REGISTER_R9D};
        constexpr reg r10d{ZYDIS_REGISTER_R10D};
        constexpr reg r11d{ZYDIS_REGISTER_R11D};
        constexpr reg r12d{ZYDIS_REGISTER_R12D};
        constexpr reg r13d{ZYDIS_REGISTER_R13D};
        constexpr reg r14d{ZYDIS_REGISTER_R14D};
        constexpr reg r15d{ZYDIS_REGISTER_R15D};

        // 64-bit
        constexpr reg rax{ZYDIS_REGISTER_RAX};
        constexpr reg rcx{ZYDIS_REGISTER_RCX};
        constexpr reg rdx{ZYDIS_REGISTER_RDX};
        constexpr reg rbx{ZYDIS_REGISTER_RBX};

        constexpr reg rsp{ZYDIS_REGISTER_RSP};
        constexpr reg rbp{ZYDIS_REGISTER_RBP};
        constexpr reg rsi{ZYDIS_REGISTER_RSI};
        constexpr reg rdi{ZYDIS_REGISTER_RDI};

        constexpr reg r8{ZYDIS_REGISTER_R8};
        constexpr reg r9{ZYDIS_REGISTER_R9};
        constexpr reg r10{ZYDIS_REGISTER_R10};
        constexpr reg r11{ZYDIS_REGISTER_R11};
        constexpr reg r12{ZYDIS_REGISTER_R12};
        constexpr reg r13{ZYDIS_REGISTER_R13};
        constexpr reg r14{ZYDIS_REGISTER_R14};
        constexpr reg r15{ZYDIS_REGISTER_R15};

        // clang-format on
    } // namespace registers

    /**
     * create a memory operand with a base register and optional displacement
     * [rax] = ptr(rax) || [rbp-0x10] = ptr(rbp, -0x10)
     */
    [[nodiscard]] constexpr mem ptr(reg base, ZyanI64 disp = 0, ZyanU16 size_override = 0) {
        return mem{.base = base.value, .disp = disp, .size_override = size_override};
    }

    /**
     * create a memory operand with an absolute address (displacement only)
     * ptr(0x12345678) = [0x12345678]
     */
    [[nodiscard]] constexpr mem ptr(ZyanU64 absolute_disp, ZyanU16 size_override = 0) {
        return mem{
                .base = ZYDIS_REGISTER_NONE,
                .disp = static_cast<ZyanI64>(absolute_disp),
                .size_override = size_override
        };
    }

    /**
     * create a memory operand with [base] [index] [scale] and optional displacement
     * ptr(rax, rbx, 4, 0x20) = [rax + rbx*4 + 0x20]
     */
    [[nodiscard]] constexpr mem
    ptr(reg base, reg index, ZyanU8 scale, ZyanI64 disp = 0, ZyanU16 size_override = 0) {
        return mem{
                .base = base.value,
                .index = index.value,
                .scale = scale,
                .disp = disp,
                .size_override = size_override
        };
    }

    struct instruction {
    private:
        ZydisEncoderRequest m_request{};

        instruction(ZydisMnemonic mnemonic) {
            m_request.mnemonic = mnemonic;
        }

        void add_operand(const operand& op) {
            if (m_request.operand_count >= ZYDIS_ENCODER_MAX_OPERANDS) {
                throw std::runtime_error("exceeded maximum number of operands for an instruction");
            }

            auto& enc_op = m_request.operands[m_request.operand_count++];

            std::visit(
                    [&](auto&& arg) {
                        using T = std::decay_t<decltype(arg)>;
                        if constexpr (std::is_same_v<T, reg>) {
                            enc_op.type = ZYDIS_OPERAND_TYPE_REGISTER;
                            enc_op.reg.value = arg.value;
                        } else if constexpr (std::is_same_v<T, imm>) {
                            enc_op.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
                            enc_op.imm.s = arg.value;
                        } else if constexpr (std::is_same_v<T, mem>) {
                            enc_op.type = ZYDIS_OPERAND_TYPE_MEMORY;
                            enc_op.mem.base = arg.base;
                            enc_op.mem.index = arg.index;
                            enc_op.mem.scale = arg.scale;
                            enc_op.mem.displacement = arg.disp;
                            if (arg.size_override > 0) {
                                enc_op.mem.size = arg.size_override;
                            }
                        }
                    },
                    op
            );
        }

        friend instruction mov(operand dst, operand src);
        friend instruction jmp(operand target);
        friend instruction nop();
        friend class code_block;

    public:
        [[nodiscard]] std::vector<std::uint8_t> encode() const {
            ZydisEncoderRequest req = m_request;
            req.machine_mode = zydis::decoder.machine_mode;

            std::vector<std::uint8_t> result_bytes(ZYDIS_MAX_INSTRUCTION_LENGTH);
            ZyanUSize encoded_length = result_bytes.size();

            const ZyanStatus status =
                    ZydisEncoderEncodeInstruction(&req, result_bytes.data(), &encoded_length);

            if (!ZYAN_SUCCESS(status)) {
                throw std::runtime_error("failed to encode instruction");
            }

            result_bytes.resize(encoded_length);
            return result_bytes;
        }
    };

    class code_block {
    private:
        std::vector<instruction> m_instructions;

    public:
        // to append an instruction to a block
        code_block& operator<<(instruction&& instr) {
            m_instructions.push_back(std::move(instr));
            return *this;
        }

        [[nodiscard]] std::vector<std::uint8_t> encode() const {
            std::vector<std::uint8_t> result;
            for (const auto& instr : m_instructions) {
                auto bytes = instr.encode();
                result.insert(result.end(), bytes.begin(), bytes.end());
            }
            return result;
        }
    };

    [[nodiscard]] instruction mov(operand dst, operand src) {
        instruction instr(ZYDIS_MNEMONIC_MOV);
        instr.add_operand(dst);
        instr.add_operand(src);
        return instr;
    }

    [[nodiscard]] instruction jmp(operand target) {
        instruction instr(ZYDIS_MNEMONIC_JMP);
        instr.add_operand(target);
        return instr;
    }

    [[nodiscard]] instruction nop() {
        return instruction(ZYDIS_MNEMONIC_NOP);
    }

} // namespace zydis::assembler
