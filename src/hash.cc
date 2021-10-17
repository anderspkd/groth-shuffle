#include "hash.h"

#include <cstring>
#include <vector>

static const uint64_t keccakf_rndc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

static const unsigned int keccakf_rotc[24] = {1,  3,  6,  10, 15, 21, 28, 36,
                                              45, 55, 2,  14, 27, 41, 56, 8,
                                              25, 43, 62, 18, 39, 61, 20, 44};

static const unsigned int keccakf_piln[24] = {10, 7,  11, 17, 18, 3,  5,  16,
                                              8,  21, 24, 4,  15, 23, 19, 13,
                                              12, 2,  20, 14, 22, 9,  6,  1};

static inline uint64_t rotl64(uint64_t x, uint64_t y) {
  return (x << y) | (x >> ((sizeof(uint64_t) * 8) - y));
}

static inline void keccakf(uint64_t state[25]) {
  uint64_t t;
  uint64_t bc[5];

  for (std::size_t round = 0; round < 24; ++round) {
    for (std::size_t i = 0; i < 5; ++i)
      bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^
              state[i + 20];

    for (std::size_t i = 0; i < 5; ++i) {
      t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
      for (std::size_t j = 0; j < 25; j += 5) state[j + i] ^= t;
    }

    t = state[1];
    for (std::size_t i = 0; i < 24; ++i) {
      const uint64_t v = keccakf_piln[i];
      bc[0] = state[v];
      state[v] = rotl64(t, keccakf_rotc[i]);
      t = bc[0];
    }

    for (std::size_t j = 0; j < 25; j += 5) {
      for (std::size_t i = 0; i < 5; ++i) bc[i] = state[j + i];
      for (std::size_t i = 0; i < 5; ++i)
        state[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
    }

    state[0] ^= keccakf_rndc[round];
  }
}

shf::Hash& shf::Hash::Update(const uint8_t* bytes, std::size_t nbytes) {
  unsigned int old_tail = (8 - mByteIndex) & 7;
  const uint8_t* p = bytes;

  if (nbytes < old_tail) {
    while (nbytes--) mSaved |= (uint64_t)(*(p++)) << ((mByteIndex++) * 8);
    return *this;
  }

  if (old_tail) {
    nbytes -= old_tail;
    while (old_tail--) mSaved |= (uint64_t)(*(p++)) << ((mByteIndex++) * 8);

    mState[mWordIndex] ^= mSaved;
    mByteIndex = 0;
    mSaved = 0;

    if (++mWordIndex == kCutoff) {
      keccakf(mState);
      mWordIndex = 0;
    }
  }

  std::size_t words = nbytes / sizeof(uint64_t);
  unsigned int tail = nbytes - words * sizeof(uint64_t);

  for (std::size_t i = 0; i < words; ++i) {
    const uint64_t t =
        (uint64_t)(p[0]) | ((uint64_t)(p[1]) << 8 * 1) |
        ((uint64_t)(p[1]) << 8 * 2) | ((uint64_t)(p[1]) << 8 * 3) |
        ((uint64_t)(p[1]) << 8 * 4) | ((uint64_t)(p[1]) << 8 * 5) |
        ((uint64_t)(p[1]) << 8 * 6) | ((uint64_t)(p[1]) << 8 * 7);

    mState[mWordIndex] ^= t;

    if (++mWordIndex == kCutoff) {
      keccakf(mState);
      mWordIndex = 0;
    }
    p += sizeof(uint64_t);
  }

  while (tail--) mSaved |= (uint64_t)(*(p++)) << ((mByteIndex++) * 8);

  return *this;
}

shf::Hash& shf::Hash::Update(const shf::Point& point) {
  // TODO: figure out if this data can be allocated automatically.
  uint8_t* data = new uint8_t[Point::ByteSize()];
  point.Write(data);
  Update(data, Point::ByteSize());
  delete[] data;
  return *this;
}

shf::Hash& shf::Hash::Update(const shf::Scalar& scalar) {
  const auto n = Scalar::ByteSize();
  uint8_t data[n];
  scalar.Write(data);
  Update(data, n);
  return *this;
}

shf::Digest shf::Hash::Finalize() {
  uint64_t t = (uint64_t)(((uint64_t)(0x02 | (1 << 2))) << ((mByteIndex)*8));
  mState[mWordIndex] ^= mSaved ^ t;
  mState[kCutoff - 1] ^= 0x8000000000000000ULL;
  keccakf(mState);

  for (std::size_t i = 0; i < kStateSize; ++i) {
    const unsigned int t1 = (uint32_t)mState[i];
    const unsigned int t2 = (uint32_t)((mState[i] >> 16) >> 16);
    mStateBytes[i * 8 + 0] = (uint8_t)t1;
    mStateBytes[i * 8 + 1] = (uint8_t)(t1 >> 8);
    mStateBytes[i * 8 + 2] = (uint8_t)(t1 >> 16);
    mStateBytes[i * 8 + 3] = (uint8_t)(t1 >> 24);
    mStateBytes[i * 8 + 4] = (uint8_t)t2;
    mStateBytes[i * 8 + 5] = (uint8_t)(t2 >> 8);
    mStateBytes[i * 8 + 6] = (uint8_t)(t2 >> 16);
    mStateBytes[i * 8 + 7] = (uint8_t)(t2 >> 24);
  }

  // truncate
  shf::Digest digest = {0};
  for (std::size_t i = 0; i < digest.size(); ++i) digest[i] = mStateBytes[i];

  return digest;
}

bool shf::DigestEquals(const shf::Digest& a, const shf::Digest& b) {
  uint8_t equal = 0;
  for (std::size_t i = 0; i < shf::Hash::DigestSize(); ++i) equal |= a[i] ^ b[i];
  return equal == 0;
}

shf::Scalar shf::ScalarFromHash(const shf::Hash& hash) {
  auto copy(hash);
  const auto d = copy.Finalize();
  return shf::Scalar::Read(d.data());
}
