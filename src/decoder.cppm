module;
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <Zydis/Zydis.h>

export module zydis:decoder;

export namespace zydis {
    ZydisDecoder decoder{};
    ZydisFormatter formatter{};
    std::array<char, 512> format_buffer{};

    // TODO: add getters for the information from the internal zydis structures
    struct instruction {
        ZydisDecodedInstruction decoded{};
        std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands{};
    };

    std::optional<std::string> format(const instruction& target_instruction) {
        const ZyanStatus status = ZydisFormatterFormatInstruction(
                &formatter, &target_instruction.decoded, target_instruction.operands.data(),
                target_instruction.operands.size(), format_buffer.data(), format_buffer.size(),
                ZYDIS_RUNTIME_ADDRESS_NONE, nullptr
        );
        if (!ZYAN_SUCCESS(status)) {
            return std::nullopt;
        }

        return format_buffer.data();
    }

    std::optional<instruction> disassemble(std::uint8_t const* const address) {
        instruction result{};
        const ZyanStatus status = ZydisDecoderDecodeFull(
                &decoder, address, ZYDIS_MAX_INSTRUCTION_LENGTH, &result.decoded, result.operands.data()
        );
        if (!ZYAN_SUCCESS(status)) {
            return std::nullopt;
        }

        return result;
    }

    std::optional<std::pair<instruction, std::string>> disassemble_format(std::uint8_t const* const address) {
        instruction result{};
        const ZyanStatus status = ZydisDecoderDecodeFull(
                &decoder, address, ZYDIS_MAX_INSTRUCTION_LENGTH, &result.decoded, result.operands.data()
        );
        if (!ZYAN_SUCCESS(status)) {
            return std::nullopt;
        }

        const auto formatted_instruction = format(result);
        if (!formatted_instruction) {
            return std::nullopt;
        }

        return std::make_pair(result, *formatted_instruction);
    }

    std::optional<std::vector<instruction>>
    disassemble(std::uint8_t const* const address, const std::size_t instruction_count) {
        std::vector<instruction> instructions;
        instructions.reserve(instruction_count);

        std::uint8_t const* current_instruction_address = address;

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

    std::optional<std::vector<std::pair<instruction, std::string>>>
    disassemble_format(std::uint8_t const* const address, const std::size_t instruction_count) {
        std::vector<std::pair<instruction, std::string>> instructions;
        instructions.reserve(instruction_count);

        std::uint8_t const* current_instruction_address = address;

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
