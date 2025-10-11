import zydis;

#include <print>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

int main() {
  if(!zydis::init(ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64, ZYDIS_FORMATTER_STYLE_INTEL)) {
    std::println(stderr, "failed to initialize zydis");
    return 1;
  }

  using namespace zydis::assembler;

  auto program = code_block{}
    << mov(registers::rax, imm{0x69})
    << mov(registers::rdx, imm{0x69})
    << add(registers::rax, registers::rdx)
    << mov(qword_ptr(registers::rcx), registers::rax)
    << ret();

  const auto encoded = program.encode();
  void* exec_mem = nullptr;
  const std::size_t code_size = encoded.size();

  #ifdef _WIN32
  exec_mem = VirtualAlloc(nullptr, code_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  #else
  exec_mem = mmap(nullptr, code_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  #endif

  if (!exec_mem) {
    std::println(stderr, "failed to allocate executable memory");
    return 1;
  }

  std::memcpy(exec_mem, encoded.data(), code_size);

  using function_t = std::uint64_t (*)(std::uint64_t*);
  auto generated_function = reinterpret_cast<function_t>(exec_mem);

  std::uint64_t result = 0;
  const std::uint64_t ret_val = generated_function(&result);

  std::println("{:x}", result);

  return 0;
}
