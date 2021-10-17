#ifndef SHF_CURVE_H
#define SHF_CURVE_H

#include <gmp.h>

#include <cstdint>

extern "C" {
#include "include/relic/relic.h"
}

namespace shf {

/**
 * @brief Initializes relic. Must be called before anything else.
 */
void CurveInit();

class Point;

class Scalar {
 public:
  // internal access needed for scalar multiplications.
  friend class Point;

  static Scalar CreateRandom();
  static Scalar CreateFromInt(unsigned int v);
  static Scalar Read(const uint8_t* bytes);

  static constexpr std::size_t ByteSize() { return 32; };

  Scalar();
  ~Scalar();

  Scalar(const Scalar& other);
  Scalar(Scalar&& other);

  Scalar& operator=(const Scalar& other);
  Scalar& operator=(Scalar&& other);

  bool IsZero() const;

  Scalar operator+(const Scalar& other) const;
  Scalar operator-(const Scalar& other) const;
  Scalar operator*(const Scalar& other) const;

  Scalar operator-() const;

  Scalar& operator+=(const Scalar& other);
  Scalar& operator-=(const Scalar& other);
  Scalar& operator*=(const Scalar& other);

  bool operator==(const Scalar& other) const;
  bool operator!=(const Scalar& other) const { return !(*this == other); };

  void Write(uint8_t* dest) const;

  void Print() const { bn_print(m_internal); }

 private:
  bn_t m_internal;
};

class Point {
 public:
  static Point Generator();
  static Point CreateRandom();
  static Point Read(const uint8_t* bytes);

  static std::size_t ByteSize() { return 2 + RLC_FP_BYTES; };

  Point();
  ~Point();

  Point(const Point& other);
  Point(Point&& other);

  Point& operator=(const Point& other);
  Point& operator=(Point&& other);

  bool IsInfinity() const;

  Point operator+(const Point& other) const;
  Point operator-(const Point& other) const;

  Point& operator+=(const Point& other);
  Point& operator-=(const Point& other);

  Point operator*(const Scalar& scalar) const;
  friend Point operator*(const Scalar& scalar, const Point& point) {
    return point * scalar;
  };

  bool operator==(const Point& other) const;
  bool operator!=(const Point& other) const { return !(*this == other); }

  void Write(uint8_t* dest) const;

  void Print() const { ec_print(m_internal); }

 private:
  ec_t m_internal;
};

}  // namespace mh
#endif  // SHF_CURVE_H
