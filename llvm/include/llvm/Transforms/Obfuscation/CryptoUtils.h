//===- CryptoUtils.h - Cryptographically Secure Pseudo-Random Generator ---===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains includes and defines for the obfuscation PRNG.
// The original implementation was AES-CTR-based; it has since been updated
// to rely on a xoshiro stream generator with deterministic seeding.
//===----------------------------------------------------------------------===//
#ifndef _OBFUSCATION_CRYPTUTILS_H
#define _OBFUSCATION_CRYPTUTILS_H

#include "llvm/Support/ManagedStatic.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace llvm {

class CryptoUtils;
class Function;
extern ManagedStatic<CryptoUtils> cryptoutils;

#define BYTE(x, n) (((x) >> (8 * (n))) & 0xFF)

#if defined(__i386) || defined(__i386__) || defined(_M_IX86) ||                \
    defined(INTEL_CC) || defined(_WIN64) || defined(_WIN32)

#ifndef ENDIAN_LITTLE
#define ENDIAN_LITTLE
#endif
#define ENDIAN_32BITWORD

#if !defined(_WIN64) || !defined(_WIN32)
#ifndef UNALIGNED
#define UNALIGNED
#endif
#endif

#elif defined(__alpha)

#ifndef ENDIAN_LITTLE
#define ENDIAN_LITTLE
#endif
#define ENDIAN_64BITWORD

#elif defined(__x86_64__)

#ifndef ENDIAN_LITTLE
#define ENDIAN_LITTLE
#endif
#define ENDIAN_64BITWORD
#define UNALIGNED

#elif (defined(__R5900) || defined(R5900) || defined(__R5900__)) &&            \
    (defined(_mips) || defined(__mips__) || defined(mips))

#ifndef ENDIAN_LITTLE
#define ENDIAN_LITTLE
#endif
#define ENDIAN_64BITWORD

#elif defined(__sparc) || defined(__aarch64__)

#ifndef ENDIAN_BIG
#define ENDIAN_BIG
#endif
#if defined(__arch64__) || defined(__aarch64__)
#define ENDIAN_64BITWORD
#else
#define ENDIAN_32BITWORD
#endif

#endif

#if defined(__BIG_ENDIAN__) || defined(_BIG_ENDIAN)
#define ENDIAN_BIG
#endif

#if !defined(ENDIAN_BIG) && !defined(ENDIAN_LITTLE)
#error                                                                         \
    "Unknown endianness of the compilation platform, check this header aes_encrypt.h"
#endif

class CryptoUtils {
public:
  CryptoUtils();
  ~CryptoUtils();

  char *get_seed();
  void get_bytes(char *buffer, const int len);
  char get_char();
  bool prng_seed(std::string const &seed);
  void seedFor(Function &F);

  // Returns a uniformly distributed 8-bit value
  uint8_t get_uint8_t();
  // Returns a uniformly distributed 32-bit value
  uint32_t get_uint32_t();
  // Returns an integer uniformly distributed on [0, max[
  uint32_t get_range(const uint32_t max);
  // Returns a uniformly distributed 64-bit value
  uint64_t get_uint64_t();

  // Scramble a 32-bit value depending on a 128-bit value
  unsigned scramble32(const unsigned in, const char key[16]);

  int sha256(const char *msg, unsigned char *hash);

private:
  std::array<uint64_t, 4> State;
  std::array<uint8_t, 32> LastSeedBytes;
  uint64_t BytePool;
  unsigned AvailableBytes;
  std::string seed;
  bool seeded;

  typedef struct {
    uint64_t length;
    uint32_t state[8], curlen;
    unsigned char buf[64];
  } sha256_state;

  void applySeed(const uint8_t *SeedMaterial, std::size_t Length);
  uint64_t next64();
  bool prng_seed();
  int sha256_done(sha256_state *md, unsigned char *out);
  int sha256_init(sha256_state *md);
  static int sha256_compress(sha256_state *md, unsigned char *buf);
  int sha256_process(sha256_state *md, const unsigned char *in,
                     unsigned long inlen);
};
} // namespace llvm

#endif
