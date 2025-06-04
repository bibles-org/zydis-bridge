module;
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <Zydis/Zydis.h>

export module zydis;

namespace zydis {
    ZydisDecoder decoder{};
    ZydisFormatter formatter{};
    std::array<char, 512> formatter_buffer{};

    // TODO: add getters for the information from the internal zydis structures
    export struct instruction {
        ZydisDecodedInstruction decoded{};
        std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands{};
    };

    export bool init(const ZydisMachineMode mode, const ZydisStackWidth stack_width, const ZydisFormatterStyle formatter_style) {
        if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, mode, stack_width))) {
            return false;
        }

        if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, formatter_style))) {
            return false;
        }

        return true;
    }

    export std::optional<instruction> disassemble(std::uint8_t const* const address) {
        instruction result{};
        const ZyanStatus status = ZydisDecoderDecodeFull(
                &decoder, address, ZYDIS_MAX_INSTRUCTION_LENGTH, &result.decoded, result.operands.data()
        );

        if (ZYAN_SUCCESS(status)) {
            return std::nullopt;
        }

        return result;
    }

    export std::optional<std::pair<instruction, std::string>> disassemble_format(std::uint8_t const* const address) {
        instruction result{};
        ZyanStatus status = ZydisDecoderDecodeFull(
                &decoder, address, ZYDIS_MAX_INSTRUCTION_LENGTH, &result.decoded, result.operands.data()
        );

        if (!ZYAN_SUCCESS(status)) {
            return std::nullopt;
        }

        status = ZydisFormatterFormatInstruction(
                &formatter, &result.decoded, result.operands.data(), result.operands.size(), formatter_buffer.data(),
                formatter_buffer.size(), ZYDIS_RUNTIME_ADDRESS_NONE, nullptr
        );

        if (!ZYAN_SUCCESS(status)) {
            return std::nullopt;
        }

        return std::make_pair(result, std::string(formatter_buffer.data()));
    }

    export std::optional<std::vector<instruction>>
    disassemble(std::uint8_t const* const address, const std::size_t instruction_count) {
        std::vector<instruction> instructions;
        instructions.reserve(instruction_count);

        const std::uint8_t* current_instruction_address = address;

        for (std::size_t i = 0; i < instruction_count; ++i) {
            auto current_instruction = disassemble(current_instruction_address);
            if (!current_instruction) {
                return std::nullopt;
            }

            instructions.emplace_back(*current_instruction);
            current_instruction_address += current_instruction->decoded.length;
        }

        return instructions;
    }

    export std::optional<std::vector<std::pair<instruction, std::string>>>
    disassemble_format(std::uint8_t const* const address, const std::size_t instruction_count) {
        std::vector<std::pair<instruction, std::string>> instructions;
        instructions.reserve(instruction_count);

        const std::uint8_t* current_instruction_address = address;

        for (std::size_t i = 0; i < instruction_count; ++i) {
            auto current_instruction = disassemble_format(current_instruction_address);
            if (!current_instruction) {
                return std::nullopt;
            }

            instructions.emplace_back(*current_instruction);
            current_instruction_address += current_instruction->first.decoded.length;
        }

        return instructions;
    }
} // namespace zydis
