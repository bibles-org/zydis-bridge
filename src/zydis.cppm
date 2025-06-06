module;
#include <Zydis/Zydis.h>

export module zydis;
export import :decoder;

namespace zydis {
    export bool
    init(const ZydisMachineMode mode, const ZydisStackWidth stack_width, const ZydisFormatterStyle formatter_style) {
        if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, mode, stack_width))) {
            return false;
        }

        if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, formatter_style))) {
            return false;
        }

        return true;
    }
} // namespace zydis
