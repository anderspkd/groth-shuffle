#define CATCH_CONFIG_ENABLE_BENCHMARKING
#include <catch2/catch.hpp>
#include <vector>

#include "shuffler.h"

#define ENABLE_BENCHMARKS 0

TEST_CASE("shuffle") {
  shf::CurveInit();

  std::size_t n = 150;

  const auto ck = shf::CreateCommitKey(n);
  const auto sk = shf::CreateSecretKey();
  const auto pk = shf::CreatePublicKey(sk);

  std::vector<shf::Point> messages;
  std::vector<shf::Ctxt> ctxts;
  for (std::size_t i = 0; i < n; ++i) {
    const auto m = shf::Point::CreateRandom();
    ctxts.emplace_back(shf::Encrypt(pk, m));
    messages.emplace_back(m);
  }

  shf::Prg prg;
  shf::Shuffler shuffler(pk, ck, prg);

  shf::ShuffleP shuffle_proof;

#if ENABLE_BENCHMARKS
  BENCHMARK("prove") {
#endif
    shf::Hash hp;
    shuffle_proof = shuffler.Shuffle(ctxts, hp);
#if ENABLE_BENCHMARKS
    return shuffle_proof;
  };
#endif

  auto shuffled = shuffle_proof.permuted;
  REQUIRE(shuffled.size() == ctxts.size());

  // brute-force check that all permuted ciphertexts are also re-randomized.
  bool good = true;
  for (std::size_t i = 0; i < ctxts.size(); i++) {
    for (std::size_t j = i + 1; j < shuffled.size(); j++) {
      good &= ctxts[i].V != shuffled[j].V;
      good &= ctxts[i].U != shuffled[j].U;
    }
  }

  bool correct = false;
#if ENABLE_BENCHMARKS
  BENCHMARK("verify") {
#endif
    shf::Hash hv;
    correct = shuffler.VerifyShuffle(ctxts, shuffle_proof, hv);
#if ENABLE_BENCHMARKS
    return correct;
  };
#endif
  REQUIRE(correct);
}
