// move this to a repository already

module;
#include <bit>
#include <compare>
#include <cstdint>
#include <format>
#include <type_traits>

export module address;

export namespace utils {
    template <typename T>
    concept is_address = std::is_trivially_copyable_v<T> && sizeof(T) <= sizeof(std::uintptr_t) &&
                         (std::is_pointer_v<T> || std::is_integral_v<T> || std::is_null_pointer_v<T>);

    struct address {
    private:
        template <is_address T>
        constexpr address& assign(const T& from) {
            if constexpr (std::is_integral_v<T> && sizeof(T) < sizeof(value)) {
                *this = static_cast<decltype(value)>(from);
            } else {
                *this = std::bit_cast<address>(from);
            }
            return *this;
        }

    public:
        std::uintptr_t value{};

        constexpr address() = default;

        constexpr address(const is_address auto& from) {
            assign(from);
        }

        constexpr address& operator=(const is_address auto& from) {
            return assign(from);
        }

        constexpr operator void*() const {
            return std::bit_cast<void*>(*this);
        }
        constexpr operator std::uintptr_t() const {
            return std::bit_cast<std::uintptr_t>(*this);
        }

        template <is_address T>
        explicit constexpr operator T() const {
            return std::bit_cast<T>(*this);
        }

        template <typename T>
            requires std::is_function_v<T>
        explicit constexpr operator T*() const {
            return reinterpret_cast<T*>(value);
        }

        explicit constexpr operator bool() const {
            return static_cast<bool>(static_cast<std::uint64_t>(*this));
        }

        constexpr address operator*() const {
            return *static_cast<void**>(*this);
        }

        friend constexpr address operator+(const address& lhs, const address& rhs) {
            return static_cast<std::uint64_t>(lhs) + static_cast<std::uint64_t>(rhs);
        }

        friend constexpr address operator+(const address& lhs, const is_address auto& rhs) {
            return static_cast<std::uint64_t>(lhs) + static_cast<std::uint64_t>(rhs);
        }

        friend constexpr address operator+(const is_address auto& lhs, const address& rhs) {
            return static_cast<std::uint64_t>(lhs) + static_cast<std::uint64_t>(rhs);
        }

        friend constexpr address operator-(const address& lhs, const address& rhs) {
            return static_cast<std::uint64_t>(lhs) - static_cast<std::uint64_t>(rhs);
        }

        friend constexpr address operator-(const address& lhs, const is_address auto& rhs) {
            return static_cast<std::uint64_t>(lhs) - static_cast<std::uint64_t>(rhs);
        }

        friend constexpr address operator-(const is_address auto& lhs, const address& rhs) {
            return static_cast<std::uint64_t>(lhs) - static_cast<std::uint64_t>(rhs);
        }

        friend constexpr address operator<<(const address& lhs, const address& rhs) {
            return static_cast<std::uint64_t>(lhs) << static_cast<std::uint64_t>(rhs);
        }

        friend constexpr address operator<<(const address& lhs, const is_address auto& rhs) {
            return lhs << static_cast<address>(rhs);
        }

        friend constexpr address operator<<(const is_address auto& lhs, const address& rhs) {
            return static_cast<address>(lhs) << rhs;
        }

        friend constexpr address operator>>(const address& lhs, const address& rhs) {
            return static_cast<std::uint64_t>(lhs) >> static_cast<std::uint64_t>(rhs);
        }

        friend constexpr address operator>>(const address& lhs, const is_address auto& rhs) {
            return lhs >> static_cast<address>(rhs);
        }

        friend constexpr address operator>>(const is_address auto& lhs, const address& rhs) {
            return static_cast<address>(lhs) >> rhs;
        }

        friend constexpr address operator&(const address& lhs, const address& rhs) {
            return static_cast<std::uint64_t>(lhs) & static_cast<std::uint64_t>(rhs);
        }

        friend constexpr address operator&(const address& lhs, const is_address auto& rhs) {
            return lhs & static_cast<address>(rhs);
        }

        friend constexpr address operator&(const is_address auto& lhs, const address& rhs) {
            return static_cast<address>(lhs) & rhs;
        }


        friend constexpr address operator|(const address& lhs, const address& rhs) {
            return static_cast<std::uint64_t>(lhs) | static_cast<std::uint64_t>(rhs);
        }

        friend constexpr address operator|(const address& lhs, const is_address auto& rhs) {
            return lhs | static_cast<address>(rhs);
        }

        friend constexpr address operator|(const is_address auto& lhs, const address& rhs) {
            return static_cast<address>(lhs) | rhs;
        }

        friend constexpr address operator^(const address& lhs, const address& rhs) {
            return static_cast<std::uint64_t>(lhs) ^ static_cast<std::uint64_t>(rhs);
        }

        friend constexpr address operator^(const address& lhs, const is_address auto& rhs) {
            return lhs ^ static_cast<address>(rhs);
        }

        friend constexpr address operator^(const is_address auto& lhs, const address& rhs) {
            return static_cast<address>(lhs) ^ rhs;
        }

        constexpr address operator~() const {
            return ~static_cast<std::uint64_t>(*this);
        }

        constexpr address& operator+=(const address& delta) {
            return *this = *this + delta;
        }

        constexpr address& operator+=(const is_address auto& delta) {
            return *this = *this + delta;
        }

        constexpr address& operator-=(const address& delta) {
            return *this = *this - delta;
        }

        constexpr address& operator-=(const is_address auto& delta) {
            return *this = *this - delta;
        }

        constexpr address& operator<<=(const address& shift) {
            return *this = *this << shift;
        }

        constexpr address& operator<<=(const is_address auto& shift) {
            return *this = *this << shift;
        }

        constexpr address& operator>>=(const address& shift) {
            return *this = *this >> shift;
        }

        constexpr address& operator>>=(const is_address auto& shift) {
            return *this = *this >> shift;
        }

        constexpr address& operator&=(const address& other) {
            return *this = *this & other;
        }

        constexpr address& operator&=(const is_address auto& other) {
            return *this = *this & other;
        }

        constexpr address& operator|=(const address& other) {
            return *this = *this | other;
        }

        constexpr address& operator|=(const is_address auto& other) {
            return *this = *this | other;
        }

        constexpr address& operator^=(const address& val) {
            return *this = *this ^ val;
        }

        constexpr address& operator^=(const is_address auto& val) {
            return *this = *this ^ val;
        }

        constexpr address& operator++() {
            *this += 1;
            return *this;
        }

        constexpr address operator++(int) {
            const address temp = *this;
            ++(*this);
            return temp;
        }

        constexpr address& operator--() {
            *this -= 1;
            return *this;
        }

        constexpr address operator--(int) {
            const address temp = *this;
            --(*this);
            return temp;
        }

        friend constexpr bool operator==(const address& lhs, const address& rhs) {
            return static_cast<std::uint64_t>(lhs) == static_cast<std::uint64_t>(rhs);
        }

        friend constexpr bool operator==(const address& lhs, const is_address auto& rhs) {
            return lhs == static_cast<address>(rhs);
        }

        friend constexpr bool operator==(const is_address auto& lhs, const address& rhs) {
            return static_cast<address>(lhs) == rhs;
        }

        friend constexpr bool operator!=(const address& lhs, const address& rhs) {
            return !(lhs == rhs);
        }

        friend constexpr bool operator!=(const address& lhs, const is_address auto& rhs) {
            return !(lhs == rhs);
        }

        friend constexpr bool operator!=(const is_address auto& lhs, const address& rhs) {
            return !(lhs == rhs);
        }

        friend constexpr auto operator<=>(const address& lhs, const address& rhs) {
            return static_cast<std::uint64_t>(lhs) <=> static_cast<std::uint64_t>(rhs);
        }

        friend constexpr auto operator<=>(const address& lhs, const is_address auto& rhs) {
            return lhs <=> static_cast<address>(rhs);
        }

        friend constexpr auto operator<=>(const is_address auto& lhs, const address& rhs) {
            return static_cast<address>(lhs) <=> rhs;
        }
    };
} // namespace utils

template <typename CharT>
struct std::formatter<utils::address, CharT> : std::formatter<std::uintptr_t, CharT> {
    auto format(const utils::address& addr, auto& ctx) const {
        return std::formatter<std::uintptr_t, CharT>::format(static_cast<std::uintptr_t>(addr), ctx);
    }
};

template <>
struct std::hash<utils::address> {
    std::size_t operator()(const utils::address& addr) const noexcept {
        return std::hash<std::uintptr_t>{}(static_cast<std::uintptr_t>(addr));
    }
};
