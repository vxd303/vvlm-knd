//===- CryptoUtils.cpp - xoshiro-based Pseudo-Random Generator ------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements a xoshiro-based pseudo-random generator with
// deterministic per-function seeding.
//
// Created on: June 22, 2012
// Last modification: November 15, 2013
// Author(s): jrinaldini, pjunod
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Obfuscation/CryptoUtils.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/Process.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cctype>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#ifdef ENDIAN_LITTLE

#define STORE32H(y, x)                                                         \
  {                                                                            \
    (y)[0] = (uint8_t)(((x) >> 24) & 0xFF);                                    \
    (y)[1] = (uint8_t)(((x) >> 16) & 0xFF);                                    \
    (y)[2] = (uint8_t)(((x) >> 8) & 0xFF);                                     \
    (y)[3] = (uint8_t)(((x) >> 0) & 0xFF);                                     \
  }
#define LOAD32H(x, y)                                                          \
  {                                                                            \
    (x) = ((uint32_t)((y)[0] & 0xFF) << 24) |                                  \
          ((uint32_t)((y)[1] & 0xFF) << 16) |                                  \
          ((uint32_t)((y)[2] & 0xFF) << 8) | ((uint32_t)((y)[3] & 0xFF) << 0); \
  }

#define LOAD64H(x, y)                                                          \
  {                                                                            \
    (x) = ((uint64_t)((y)[0] & 0xFF) << 56) |                                  \
          ((uint64_t)((y)[1] & 0xFF) << 48) |                                  \
          ((uint64_t)((y)[2] & 0xFF) << 40) |                                  \
          ((uint64_t)((y)[3] & 0xFF) << 32) |                                  \
          ((uint64_t)((y)[4] & 0xFF) << 24) |                                  \
          ((uint64_t)((y)[5] & 0xFF) << 16) |                                  \
          ((uint64_t)((y)[6] & 0xFF) << 8) | ((uint64_t)((y)[7] & 0xFF) << 0); \
  }

#define STORE64H(y, x)                                                         \
  {                                                                            \
    (y)[0] = (uint8_t)(((x) >> 56) & 0xFF);                                    \
    (y)[1] = (uint8_t)(((x) >> 48) & 0xFF);                                    \
    (y)[2] = (uint8_t)(((x) >> 40) & 0xFF);                                    \
    (y)[3] = (uint8_t)(((x) >> 32) & 0xFF);                                    \
    (y)[4] = (uint8_t)(((x) >> 24) & 0xFF);                                    \
    (y)[5] = (uint8_t)(((x) >> 16) & 0xFF);                                    \
    (y)[6] = (uint8_t)(((x) >> 8) & 0xFF);                                     \
    (y)[7] = (uint8_t)(((x) >> 0) & 0xFF);                                     \
  }

#endif /* ENDIAN_LITTLE */

#ifdef ENDIAN_BIG

#define STORE32H(y, x)                                                         \
  {                                                                            \
    (y)[3] = (uint8_t)(((x) >> 24) & 0xFF);                                    \
    (y)[2] = (uint8_t)(((x) >> 16) & 0xFF);                                    \
    (y)[1] = (uint8_t)(((x) >> 8) & 0xFF);                                     \
    (y)[0] = (uint8_t)(((x) >> 0) & 0xFF);                                     \
  }
#define STORE64H(y, x)                                                         \
  {                                                                            \
    (y)[7] = (uint8_t)(((x) >> 56) & 0xFF);                                    \
    (y)[6] = (uint8_t)(((x) >> 48) & 0xFF);                                    \
    (y)[5] = (uint8_t)(((x) >> 40) & 0xFF);                                    \
    (y)[4] = (uint8_t)(((x) >> 32) & 0xFF);                                    \
    (y)[3] = (uint8_t)(((x) >> 24) & 0xFF);                                    \
    (y)[2] = (uint8_t)(((x) >> 16) & 0xFF);                                    \
    (y)[1] = (uint8_t)(((x) >> 8) & 0xFF);                                     \
    (y)[0] = (uint8_t)(((x) >> 0) & 0xFF);                                     \
  }
#define LOAD32H(x, y)                                                          \
  {                                                                            \
    (x) = ((uint32_t)((y)[3] & 0xFF) << 24) |                                  \
          ((uint32_t)((y)[2] & 0xFF) << 16) |                                  \
          ((uint32_t)((y)[1] & 0xFF) << 8) | ((uint32_t)((y)[0] & 0xFF) << 0); \
  }

#define LOAD64H(x, y)                                                          \
  {                                                                            \
    (x) = ((uint64_t)((y)[7] & 0xFF) << 56) |                                  \
          ((uint64_t)((y)[6] & 0xFF) << 48) |                                  \
          ((uint64_t)((y)[5] & 0xFF) << 40) |                                  \
          ((uint64_t)((y)[4] & 0xFF) << 32) |                                  \
          ((uint64_t)((y)[3] & 0xFF) << 24) |                                  \
          ((uint64_t)((y)[2] & 0xFF) << 16) |                                  \
          ((uint64_t)((y)[1] & 0xFF) << 8) | ((uint64_t)((y)[0] & 0xFF) << 0); \
  }

#endif /* ENDIAN_BIG */

// SHA256
/* Various logical functions */
#define Ch(x, y, z) (z ^ (x & (y ^ z)))
#define Maj(x, y, z) (((x | y) & z) | (x & y))
#define S(x, n) RORc((x), (n))
#define R1(x, n) (((x)&0xFFFFFFFFUL) >> (n))
#define Sigma0(x) (S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define Sigma1(x) (S(x, 6) ^ S(x, 11) ^ S(x, 25))
#define Gamma0(x) (S(x, 7) ^ S(x, 18) ^ R1(x, 3))
#define Gamma1(x) (S(x, 17) ^ S(x, 19) ^ R1(x, 10))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define RND(a, b, c, d, e, f, g, h, i, ki)                                     \
  t0 = h + Sigma1(e) + Ch(e, f, g) + ki + W[i];                                \
  t1 = Sigma0(a) + Maj(a, b, c);                                               \
  d += t0;                                                                     \
  h = t0 + t1;

#define RORc(x, y)                                                             \
  (((((unsigned long)(x)&0xFFFFFFFFUL) >> (unsigned long)((y)&31)) |           \
    ((unsigned long)(x) << (unsigned long)(32 - ((y)&31)))) &                  \
   0xFFFFFFFFUL)
// Stats
#define DEBUG_TYPE "CryptoUtils"
STATISTIC(statsGetBytes, "a. Number of calls to get_bytes ()");
STATISTIC(statsGetChar, "b. Number of calls to get_char ()");
STATISTIC(statsGetUint8, "c. Number of calls to get_uint8_t ()");
STATISTIC(statsGetUint32, "d. Number of calls to get_uint32_t ()");
STATISTIC(statsGetUint64, "e. Number of calls to get_uint64_t ()");
STATISTIC(statsGetRange, "f. Number of calls to get_range ()");

using namespace llvm;

namespace llvm {
ManagedStatic<CryptoUtils> cryptoutils;
}

namespace {

static inline uint64_t rotl64(uint64_t X, int K) {
  return (X << K) | (X >> (64 - K));
}

static inline uint32_t rotl32(uint32_t X, int K) {
  return (X << K) | (X >> (32 - K));
}

static std::string toHexString(const uint8_t *Data, std::size_t Length) {
  static const char *Digits = "0123456789abcdef";
  std::string Out;
  Out.reserve(Length * 2);
  for (std::size_t I = 0; I < Length; ++I) {
    uint8_t Byte = Data[I];
    Out.push_back(Digits[Byte >> 4]);
    Out.push_back(Digits[Byte & 0x0F]);
  }
  return Out;
}

static int hexValue(char C) {
  if (C >= '0' && C <= '9')
    return C - '0';
  if (C >= 'a' && C <= 'f')
    return 10 + (C - 'a');
  if (C >= 'A' && C <= 'F')
    return 10 + (C - 'A');
  return -1;
}

} // namespace

CryptoUtils::CryptoUtils()
    : BytePool(0), AvailableBytes(0), seeded(false) {
  State.fill(0);
  LastSeedBytes.fill(0);
}

unsigned CryptoUtils::scramble32(const unsigned in, const char key[16]) {
  assert(key != nullptr && "CryptoUtils::scramble key=NULL");

  const uint8_t *KeyBytes = reinterpret_cast<const uint8_t *>(key);
  uint32_t k0 = 0;
  uint32_t k1 = 0;
  uint32_t k2 = 0;
  uint32_t k3 = 0;

  for (int I = 0; I < 4; ++I) {
    k0 = (k0 << 8) | KeyBytes[I];
    k1 = (k1 << 8) | KeyBytes[I + 4];
    k2 = (k2 << 8) | KeyBytes[I + 8];
    k3 = (k3 << 8) | KeyBytes[I + 12];
  }

  uint32_t x = in ^ k0;
  x = rotl32(x + 0x9E3779B9u, 7);
  x ^= k1;
  x = (x ^ (x >> 15)) * (k2 | 1u);
  x = rotl32(x ^ (x >> 13), 11);
  x += k3 | 1u;
  x ^= (x >> 16);
  return x;
}

bool CryptoUtils::prng_seed(std::string const &SeedStr) {
  if (SeedStr.empty()) {
    errs() << "The PRNG seed must not be empty\n";
    return false;
  }

  std::string CleanSeed = SeedStr;
  std::size_t Offset = 0;
  if (CleanSeed.size() >= 2 && CleanSeed[0] == '0' &&
      (CleanSeed[1] == 'x' || CleanSeed[1] == 'X')) {
    Offset = 2;
  }

  if (((CleanSeed.size() - Offset) % 2) != 0) {
    errs() << "The PRNG seed must contain an even number of hexadecimal characters\n";
    return false;
  }

  std::vector<uint8_t> Bytes;
  Bytes.reserve((CleanSeed.size() - Offset) / 2);
  for (std::size_t I = Offset; I < CleanSeed.size(); I += 2) {
    int High = hexValue(CleanSeed[I]);
    int Low = hexValue(CleanSeed[I + 1]);
    if (High < 0 || Low < 0) {
      errs() << "Invalid hexadecimal seed provided to CryptoUtils\n";
      return false;
    }
    Bytes.push_back(static_cast<uint8_t>((High << 4) | Low));
  }

  if (Bytes.empty()) {
    errs() << "The PRNG seed cannot be empty\n";
    return false;
  }

  unsigned char Material[32];
  if (Bytes.size() == 32) {
    std::copy(Bytes.begin(), Bytes.end(), Material);
  } else {
    sha256_state MD;
    sha256_init(&MD);
    sha256_process(&MD, reinterpret_cast<const unsigned char *>(Bytes.data()),
                   Bytes.size());
    sha256_done(&MD, Material);
  }

  applySeed(Material, 32);
  seed = SeedStr;
  return true;
}

bool CryptoUtils::prng_seed() {
  std::array<uint8_t, 32> Material;
  std::random_device RD;
  for (auto &Byte : Material)
    Byte = static_cast<uint8_t>(RD());
  applySeed(Material.data(), Material.size());
  seed = toHexString(Material.data(), Material.size());
  return true;
}

CryptoUtils::~CryptoUtils() {
  State.fill(0);
  LastSeedBytes.fill(0);
  BytePool = 0;
  AvailableBytes = 0;
  seed.clear();
  seeded = false;
}

void CryptoUtils::applySeed(const uint8_t *SeedMaterial, std::size_t Length) {
  assert(SeedMaterial != nullptr);
  assert(Length >= 32 && "Seed material must be at least 32 bytes");

  std::copy(SeedMaterial, SeedMaterial + 32, LastSeedBytes.begin());

  for (unsigned I = 0; I < 4; ++I) {
    uint64_t Value = 0;
    for (unsigned J = 0; J < 8; ++J) {
      Value = (Value << 8) | SeedMaterial[I * 8 + J];
    }
    State[I] = Value;
  }

  bool AllZero =
      std::all_of(State.begin(), State.end(), [](uint64_t V) { return V == 0; });
  if (AllZero) {
    State[0] = 0x0123456789ABCDEFULL;
    State[1] = 0xF0E1D2C3B4A59687ULL;
    State[2] = 0xC3D2E1F012345678ULL;
    State[3] = 0x9E3779B97F4A7C15ULL;
  }

  BytePool = 0;
  AvailableBytes = 0;
  seeded = true;
}

uint64_t CryptoUtils::next64() {
  if (!seeded)
    prng_seed();

  uint64_t Result = rotl64(State[1] * 5, 7) * 9;
  uint64_t T = State[1] << 17;

  State[2] ^= State[0];
  State[3] ^= State[1];
  State[1] ^= State[2];
  State[0] ^= State[3];

  State[2] ^= T;
  State[3] = rotl64(State[3], 45);

  return Result;
}

void CryptoUtils::seedFor(Function &F) {
  SmallString<256> Material;
  auto Append = [&](StringRef Value) {
    if (!Value.empty()) {
      Material.append(Value.begin(), Value.end());
      Material.push_back('|');
    }
  };

  if (auto Git = sys::Process::GetEnv("GIT_COMMIT"))
    Append(*Git);
  if (auto Fingerprint = sys::Process::GetEnv("BUILD_FINGERPRINT"))
    Append(*Fingerprint);
  if (auto SourceDate = sys::Process::GetEnv("SOURCE_DATE_EPOCH"))
    Append(*SourceDate);

  if (Module *M = F.getParent()) {
    Append(M->getModuleIdentifier());
    Append(M->getSourceFileName());
  }
  Append(F.getName());

  if (Material.empty())
    Material.append(StringRef("cryptoutils"));

  sha256_state MD;
  unsigned char Hash[32];
  sha256_init(&MD);
  sha256_process(&MD,
                 reinterpret_cast<const unsigned char *>(Material.data()),
                 Material.size());
  sha256_done(&MD, Hash);

  applySeed(Hash, 32);
  seed = toHexString(Hash, 32);
}

char *CryptoUtils::get_seed() {
  return seeded ? reinterpret_cast<char *>(LastSeedBytes.data()) : nullptr;
}

void CryptoUtils::get_bytes(char *buffer, const int len) {
  assert(buffer != nullptr && "CryptoUtils::get_bytes buffer=NULL");
  assert(len > 0 && "CryptoUtils::get_bytes len <= 0");

  statsGetBytes++;

  for (int Produced = 0; Produced < len; ++Produced) {
    if (AvailableBytes == 0) {
      BytePool = next64();
      AvailableBytes = 8;
    }
    --AvailableBytes;
    buffer[Produced] =
        static_cast<char>((BytePool >> (AvailableBytes * 8)) & 0xFF);
  }
}

uint8_t CryptoUtils::get_uint8_t() {
  char Ret;

  statsGetUint8++;

  get_bytes(&Ret, 1);

  return static_cast<uint8_t>(Ret);
}

char CryptoUtils::get_char() {
  char Ret;

  statsGetChar++;

  get_bytes(&Ret, 1);

  return Ret;
}

uint32_t CryptoUtils::get_uint32_t() {
  char Tmp[4];
  uint32_t Ret = 0;

  statsGetUint32++;

  get_bytes(Tmp, 4);

  LOAD32H(Ret, Tmp);

  return Ret;
}

uint64_t CryptoUtils::get_uint64_t() {
  char Tmp[8];
  uint64_t Ret = 0;

  statsGetUint64++;

  get_bytes(Tmp, 8);

  LOAD64H(Ret, Tmp);

  return Ret;
}

uint32_t CryptoUtils::get_range(const uint32_t max) {
  statsGetRange++;

  if (max == 0)
    return 0;

  uint32_t Mask = max - 1;
  Mask |= Mask >> 1;
  Mask |= Mask >> 2;
  Mask |= Mask >> 4;
  Mask |= Mask >> 8;
  Mask |= Mask >> 16;

  uint32_t R;
  do {
    R = get_uint32_t() & Mask;
  } while (R >= max);

  return R;
}
int CryptoUtils::sha256_process(sha256_state *md, const unsigned char *in,
                                unsigned long inlen) {
  unsigned long n;
  int err;
  assert(md != NULL && "CryptoUtils::sha256_process md=NULL");
  assert(in != NULL && "CryptoUtils::sha256_process in=NULL");

  if (md->curlen > sizeof(md->buf)) {
    return 1;
  }
  while (inlen > 0) {
    if (md->curlen == 0 && inlen >= 64) {
      if ((err = sha256_compress(md, (unsigned char *)in)) != 0) {
        return err;
      }
      md->length += 64 * 8;
      in += 64;
      inlen -= 64;
    } else {
      n = MIN(inlen, (64 - md->curlen));
      memcpy(md->buf + md->curlen, in, (size_t)n);
      md->curlen += n;
      in += n;
      inlen -= n;
      if (md->curlen == 64) {
        if ((err = sha256_compress(md, md->buf)) != 0) {
          return err;
        }
        md->length += 8 * 64;
        md->curlen = 0;
      }
    }
  }
  return 0;
}

int CryptoUtils::sha256_compress(sha256_state *md, unsigned char *buf) {
  uint32_t S[8], W[64], t0, t1;
  int i;

  /* copy state into S */
  for (i = 0; i < 8; i++) {
    S[i] = md->state[i];
  }

  /* copy the state into 512-bits into W[0..15] */
  for (i = 0; i < 16; i++) {
    LOAD32H(W[i], buf + (4 * i));
  }

  /* fill W[16..63] */
  for (i = 16; i < 64; i++) {
    W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
  }

  /* Compress */

  RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 0, 0x428a2f98);
  RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 1, 0x71374491);
  RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 2, 0xb5c0fbcf);
  RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 3, 0xe9b5dba5);
  RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 4, 0x3956c25b);
  RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 5, 0x59f111f1);
  RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 6, 0x923f82a4);
  RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 7, 0xab1c5ed5);
  RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 8, 0xd807aa98);
  RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 9, 0x12835b01);
  RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 10, 0x243185be);
  RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 11, 0x550c7dc3);
  RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 12, 0x72be5d74);
  RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 13, 0x80deb1fe);
  RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 14, 0x9bdc06a7);
  RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 15, 0xc19bf174);
  RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 16, 0xe49b69c1);
  RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 17, 0xefbe4786);
  RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 18, 0x0fc19dc6);
  RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 19, 0x240ca1cc);
  RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 20, 0x2de92c6f);
  RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 21, 0x4a7484aa);
  RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 22, 0x5cb0a9dc);
  RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 23, 0x76f988da);
  RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 24, 0x983e5152);
  RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 25, 0xa831c66d);
  RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 26, 0xb00327c8);
  RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 27, 0xbf597fc7);
  RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 28, 0xc6e00bf3);
  RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 29, 0xd5a79147);
  RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 30, 0x06ca6351);
  RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 31, 0x14292967);
  RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 32, 0x27b70a85);
  RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 33, 0x2e1b2138);
  RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 34, 0x4d2c6dfc);
  RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 35, 0x53380d13);
  RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 36, 0x650a7354);
  RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 37, 0x766a0abb);
  RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 38, 0x81c2c92e);
  RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 39, 0x92722c85);
  RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 40, 0xa2bfe8a1);
  RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 41, 0xa81a664b);
  RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 42, 0xc24b8b70);
  RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 43, 0xc76c51a3);
  RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 44, 0xd192e819);
  RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 45, 0xd6990624);
  RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 46, 0xf40e3585);
  RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 47, 0x106aa070);
  RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 48, 0x19a4c116);
  RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 49, 0x1e376c08);
  RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 50, 0x2748774c);
  RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 51, 0x34b0bcb5);
  RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 52, 0x391c0cb3);
  RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 53, 0x4ed8aa4a);
  RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 54, 0x5b9cca4f);
  RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 55, 0x682e6ff3);
  RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 56, 0x748f82ee);
  RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 57, 0x78a5636f);
  RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 58, 0x84c87814);
  RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 59, 0x8cc70208);
  RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 60, 0x90befffa);
  RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 61, 0xa4506ceb);
  RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 62, 0xbef9a3f7);
  RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 63, 0xc67178f2);

  /* feedback */
  for (i = 0; i < 8; i++) {
    md->state[i] = md->state[i] + S[i];
  }
  return 0;
}

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int CryptoUtils::sha256_init(sha256_state *md) {
  assert(md != NULL && "CryptoUtils::sha256_init md=NULL");

  md->curlen = 0;
  md->length = 0;
  md->state[0] = 0x6A09E667UL;
  md->state[1] = 0xBB67AE85UL;
  md->state[2] = 0x3C6EF372UL;
  md->state[3] = 0xA54FF53AUL;
  md->state[4] = 0x510E527FUL;
  md->state[5] = 0x9B05688CUL;
  md->state[6] = 0x1F83D9ABUL;
  md->state[7] = 0x5BE0CD19UL;
  return 0;
}

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (32 bytes)
   @return CRYPT_OK if successful
*/
int CryptoUtils::sha256_done(sha256_state *md, unsigned char *out) {
  int i;

  assert(md != NULL && "CryptoUtils::sha256_done md=NULL");
  assert(out != NULL && "CryptoUtils::sha256_done out=NULL");

  if (md->curlen >= sizeof(md->buf)) {
    return 1;
  }

  /* increase the length of the message */
  md->length += md->curlen * 8;

  /* append the '1' bit */
  md->buf[md->curlen++] = (unsigned char)0x80;

  /* if the length is currently above 56 bytes we append zeros
   * then compress.  Then we can fall back to padding zeros and length
   * encoding like normal.
   */
  if (md->curlen > 56) {
    while (md->curlen < 64) {
      md->buf[md->curlen++] = (unsigned char)0;
    }
    sha256_compress(md, md->buf);
    md->curlen = 0;
  }

  /* pad upto 56 bytes of zeroes */
  while (md->curlen < 56) {
    md->buf[md->curlen++] = (unsigned char)0;
  }

  /* store length */
  STORE64H(md->buf + 56, md->length);
  sha256_compress(md, md->buf);

  /* copy output */
  for (i = 0; i < 8; i++) {
    STORE32H(out + (4 * i), md->state[i]);
  }
  return 0;
}

int CryptoUtils::sha256(const char *msg, unsigned char *hash) {
  unsigned char tmp[32];
  sha256_state md;

  sha256_init(&md);
  sha256_process(&md, (const unsigned char *)msg,
                 (unsigned long)strlen((const char *)msg));
  sha256_done(&md, tmp);

  memcpy(hash, tmp, 32);
  return 0;
}
