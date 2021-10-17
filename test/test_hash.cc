#include <catch2/catch.hpp>

#include "hash.h"

static const shf::Digest SHA3_256_empty = {
    0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47,
    0x56, 0xa0, 0x61, 0xd6, 0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b,
    0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a};

static const shf::Digest SHA3_256_abc = {
    0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17,
    0x2d, 0x6b, 0xd3, 0x90, 0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d,
    0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32};

static const shf::Digest SHA3_256_0xa3_200_times = {
    0x79, 0xf3, 0x8a, 0xde, 0xc5, 0xc2, 0x03, 0x07, 0xa9, 0x8e, 0xf7,
    0x6e, 0x83, 0x24, 0xaf, 0xbf, 0xd4, 0x6c, 0xfd, 0x81, 0xb2, 0x2e,
    0x39, 0x73, 0xc6, 0x5f, 0xa1, 0xbd, 0x9d, 0xe3, 0x17, 0x87};

TEST_CASE("hash") {
  SECTION("SHA3-256 empty") {
    shf::Hash hash;
    auto digest = hash.Finalize();
    REQUIRE(shf::DigestEquals(digest, SHA3_256_empty));
  }
  SECTION("SHA3-256 abc") {
    shf::Hash hash;
    auto digest = hash.Update((const unsigned char *)"abc", 3).Finalize();
    REQUIRE(shf::DigestEquals(digest, SHA3_256_abc));
  }
  unsigned char byte = 0xA3;
  unsigned char buf[200];
  for (std::size_t i = 0; i < 200; ++i) buf[i] = byte;

  SECTION("0xA3 x 200") {
    shf::Hash hash;
    auto digest = hash.Update(buf, 200).Finalize();
    REQUIRE(shf::DigestEquals(digest, SHA3_256_0xa3_200_times));
  }

  SECTION("0xA3 x 200 byte-by-byte") {
    shf::Hash hash;
    for (std::size_t i = 0; i < 200; ++i) hash.Update(&byte, 1);
    REQUIRE(shf::DigestEquals(hash.Finalize(), SHA3_256_0xa3_200_times));
  }

  SECTION("can copy state") {
    shf::Hash hash;
    hash.Update((const unsigned char *)"abc", 3);
    shf::Hash copy = hash;
    auto digest = hash.Finalize();
    REQUIRE(shf::DigestEquals(digest, SHA3_256_abc));
    REQUIRE(shf::DigestEquals(copy.Finalize(), SHA3_256_abc));

    // cannot call finalize multiple times on the same hash object
    REQUIRE(!shf::DigestEquals(copy.Finalize(), SHA3_256_abc));
  }
}
