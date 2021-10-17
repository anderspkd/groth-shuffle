#ifndef SHF_HASH_H
#define SHF_HASH_H

#include <array>
#include <cstdint>

#include "curve.h"

namespace shf {

using Digest = std::array<uint8_t, 32>;

bool DigestEquals(const Digest& a, const Digest& b);

class Hash {
 public:
  static constexpr std::size_t DigestSize() { return 32; };

  Hash(){};

  Hash& Update(const uint8_t* data, std::size_t n);
  Hash& Update(const Point& point);
  Hash& Update(const Scalar& scalar);

  Digest Finalize();

 private:
  static constexpr std::size_t kCapacity = 512 / (8 * sizeof(uint64_t));
  static constexpr std::size_t kStateSize = 25;
  static constexpr std::size_t kCutoff = kStateSize - (kCapacity & ~0x80000000);

  uint64_t mState[kStateSize] = {0};
  uint8_t mStateBytes[kStateSize * 8] = {0};
  uint64_t mSaved = 0;
  unsigned int mByteIndex = 0;
  unsigned int mWordIndex = 0;
};

Scalar ScalarFromHash(const Hash& hash);

}  // namespace mh

#endif  // SHF_HASH_H
