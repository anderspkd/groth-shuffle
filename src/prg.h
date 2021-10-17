#ifndef SHF_PRG_H
#define SHF_PRG_H

#include <wmmintrin.h>

#include <cstdint>
#include <vector>

namespace shf {

class Prg {
 public:
  static constexpr std::size_t BlockSize() { return sizeof(__m128i); };

  static constexpr std::size_t SeedSize() { return BlockSize(); };

  Prg();

  Prg(const uint8_t* seed);

  void Fill(uint8_t* dest, std::size_t n);

  template <typename T>
  void Fill(std::vector<T>& to_fill) {
    const auto n = to_fill.size();
    const auto data_size = sizeof(T) * n;
    uint8_t* data = new uint8_t[data_size];
    Fill(data, data_size);
    T* ptr = reinterpret_cast<T*>(data);
    for (std::size_t i = 0; i < n; ++i) to_fill[i] = *ptr++;
    delete[] data;
  }

 private:
  void Update();
  void Init();

  uint8_t m_seed[sizeof(__m128i)] = {0};
  long m_counter = 0;
  __m128i m_state[11];
};

}  // namespace mh

#endif  // SHF_PRG_H
