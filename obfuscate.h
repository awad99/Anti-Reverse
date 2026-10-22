// obfuscate.h — compile-time string encryption for exe-protector.
//
// Every string wrapped in OBF(...) is XOR-encrypted *at compile time* with a
// per-site key, so the plaintext never appears in the binary's .rdata section.
// At run time each use decrypts into a short-lived stack buffer, which is wiped
// when it goes out of scope. The net effect: tools like `strings`, a hex editor
// or a casual look in a PE inspector see only ciphertext.
//
// Scope / honesty: this defeats *static* inspection (strings, grep, hex dump).
// It is not a substitute for the anti-debug / integrity passes — a reverser who
// runs the program under a debugger can still read a string after it decrypts.
// The two layers are meant to be used together.
//
// Usage:
//   r << OBF(L"== File header ==\r\n");          // streams like a string
//   SetWindowTextW(h, OBF(L"Done"));             // converts to const wchar_t*
//   auto cls = OBF(L"MyWindowClass");            // keep a named local when the
//   RegisterClassExW(... cls ...);               //   pointer must outlive one
//   CreateWindowExW(... cls ...);                //   statement
//
// Works for both char ("...") and wchar_t (L"...") literals, including ones
// that contain embedded NULs (e.g. OPENFILENAME double-null filter strings),
// because the whole array — length included — is carried, not a C-string.

#ifndef OBFUSCATE_H
#define OBFUSCATE_H

#include <cstddef>
#include <cstdint>
#include <ostream>
#include <string>
#include <type_traits>

namespace obf {

// A splitmix64-style mix gives a well-scrambled keystream byte for position `i`
// from the per-string seed, so the key is not a trivial constant or a ramp.
constexpr std::uint64_t key_at(std::uint64_t seed, std::size_t i) {
    std::uint64_t k = seed + 0x9E3779B97F4A7C15ULL * (static_cast<std::uint64_t>(i) + 1);
    k ^= k >> 30; k *= 0xBF58476D1CE4E5B9ULL;
    k ^= k >> 27; k *= 0x94D049BB133111EBULL;
    k ^= k >> 31;
    return k;
}

// Holds the ciphertext. Being a literal type with a constexpr constructor, an
// instance declared `static constexpr` is constant-initialized — the compiler
// emits only the *encrypted* bytes into read-only data, never the source text.
template <typename CharT, std::size_t N, std::uint64_t Seed>
struct encrypted {
    CharT data[N];
    constexpr encrypted(const CharT (&src)[N]) : data{} {
        for (std::size_t i = 0; i < N; ++i)
            data[i] = static_cast<CharT>(src[i] ^ static_cast<CharT>(key_at(Seed, i)));
    }
};

// Decrypts the ciphertext into its own buffer at run time, hands it out as a
// string, and wipes the buffer on destruction so the plaintext does not linger
// on the stack. The volatile stores keep the optimizer from folding the whole
// thing back into a plaintext constant in .rdata.
template <typename CharT, std::size_t N, std::uint64_t Seed>
class decryptor {
public:
    explicit decryptor(const encrypted<CharT, N, Seed>& enc) {
        volatile CharT* out = buf_;
        for (std::size_t i = 0; i < N; ++i)
            out[i] = static_cast<CharT>(enc.data[i] ^ static_cast<CharT>(key_at(Seed, i)));
    }
    ~decryptor() {
        volatile CharT* out = buf_;
        for (std::size_t i = 0; i < N; ++i) out[i] = CharT(0);
    }

    const CharT* c_str() const { return buf_; }
    operator const CharT*() const { return buf_; }

    // Explicit copy into an owning string, for the places that need a
    // std::wstring value (e.g. a function return). A std::wstring cannot be
    // built implicitly from a decryptor — that would be two user-defined
    // conversions — so those sites spell it out with .str().
    std::basic_string<CharT> str() const {
        return std::basic_string<CharT>(buf_, (N > 0) ? N - 1 : 0);
    }

private:
    CharT buf_[N];
};

// Exact-match stream overload (beats the conversion-to-pointer path, so there
// is never any ambiguity when streaming into a wostringstream).
template <typename CharT, std::size_t N, std::uint64_t Seed>
std::basic_ostream<CharT>& operator<<(std::basic_ostream<CharT>& os,
                                      const decryptor<CharT, N, Seed>& d) {
    return os << d.c_str();
}

} // namespace obf

// __COUNTER__ makes every OBF() expansion use a distinct key, so two identical
// literals encrypt to different ciphertext and cannot be matched by eye.
#define OBF_SEED_                                                              \
    (0xC0FFEE0D15EA5EULL ^ (static_cast<std::uint64_t>(__COUNTER__) * 0x100000001B3ULL) \
     ^ (static_cast<std::uint64_t>(__LINE__) * 0x9E3779B1ULL))

#define OBF(str)                                                              \
    ([]() {                                                                   \
        using CharT_ = std::remove_const_t<std::remove_reference_t<decltype((str)[0])>>; \
        constexpr std::size_t   n_    = sizeof(str) / sizeof(CharT_);          \
        constexpr std::uint64_t seed_ = OBF_SEED_;                            \
        static constexpr obf::encrypted<CharT_, n_, seed_> enc_(str);         \
        return obf::decryptor<CharT_, n_, seed_>(enc_);                       \
    }())

#endif // OBFUSCATE_H
