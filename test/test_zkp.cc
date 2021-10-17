#include <catch2/catch.hpp>

#include "curve.h"
#include "zkp.h"

TEST_CASE("dlog") {
  shf::CurveInit();

  SECTION("create and verify") {
    shf::Scalar x = shf::Scalar::CreateRandom();
    shf::Point G = shf::Point::Generator();
    shf::Point xG = x * G;
    shf::DLogS stmt = {G, xG};
    shf::Hash hash_prover;
    shf::Hash hash_verifier;
    const auto proof = shf::CreateProof(stmt, hash_prover, x);
    REQUIRE(shf::VerifyProof(stmt, hash_verifier, proof));

    // hash_prover and hash_verifier should now have the same internal
    // state.
    const auto digest_prover = hash_prover.Finalize();
    const auto digest_verifier = hash_verifier.Finalize();
    const auto digest_zero = shf::Hash().Finalize();

    REQUIRE(shf::DigestEquals(digest_prover, digest_verifier));
    REQUIRE(!shf::DigestEquals(digest_zero, digest_prover));

    shf::DLogP bad_proof = {shf::Point::CreateRandom(),
                           shf::Scalar::CreateRandom()};
    shf::Hash h;
    REQUIRE(!shf::VerifyProof(stmt, h, bad_proof));
  }
}

TEST_CASE("dlogeq") {
  shf::CurveInit();

  SECTION("create and verify") {
    shf::Scalar x = shf::Scalar::CreateRandom();
    shf::Point G = shf::Point::CreateRandom();
    shf::Point H = shf::Point::CreateRandom();
    auto xG = x * G;
    auto xH = x * H;
    shf::DLogEqS stmt = {G, xG, H, xH};
    shf::Hash hash_prover, hash_verifier;
    auto proof = shf::CreateProof(stmt, hash_prover, x);
    REQUIRE(shf::VerifyProof(stmt, hash_verifier, proof));

    shf::Digest digest_prover = hash_prover.Finalize();
    shf::Digest digest_verifier = hash_verifier.Finalize();
    shf::Digest digest_zero = shf::Hash().Finalize();

    REQUIRE(shf::DigestEquals(digest_prover, digest_verifier));
    REQUIRE(!shf::DigestEquals(digest_zero, digest_prover));
  }
}

TEST_CASE("product") {
  shf::CurveInit();

  std::size_t n = 100;
  SECTION("create and verify") {
    std::vector<shf::Scalar> a;
    shf::Scalar p = shf::Scalar::CreateFromInt(1);
    for (std::size_t i = 0; i < n; i++) {
      shf::Scalar x = shf::Scalar::CreateRandom();
      a.emplace_back(x);
      p *= x;
    }

    shf::CommitKey ck = shf::CreateCommitKey(n);
    shf::CommitmentAndRandomness Cr = shf::Commit(ck, a);

    shf::Hash hp, hv;
    shf::ProductP proof = shf::CreateProof(ck, hp, {Cr.C, p}, a, Cr.r);
    REQUIRE(shf::VerifyProof(ck, hv, {Cr.C, p}, proof));
  }
}

static inline std::vector<shf::Ctxt> RandomCtxts(std::size_t n) {
  std::vector<shf::Ctxt> r(n);
  for (std::size_t i = 0; i < n; i++)
    r[i] = {shf::Point::CreateRandom(), shf::Point::CreateRandom()};
  return r;
}

static inline shf::Ctxt RandomizeAndDot(const std::vector<shf::Ctxt>& Es,
                                       const std::vector<shf::Scalar>& as,
                                       const shf::PublicKey& pk,
                                       const shf::Scalar& r) {
  auto E = shf::Encrypt(pk, shf::Point(), r);
  for (std::size_t i = 0; i < Es.size(); i++)
    E = shf::Add(E, shf::Multiply(as[i], Es[i]));
  return E;
}

TEST_CASE("multiexp") {
  shf::CurveInit();

  std::size_t n = 100;
  const auto sk = shf::CreateSecretKey();
  const auto pk = shf::CreatePublicKey(sk);
  const auto ck = shf::CreateCommitKey(n);
  SECTION("create and verify") {
    std::vector<shf::Ctxt> Es = RandomCtxts(n);
    std::vector<shf::Scalar> as(n);
    for (std::size_t i = 0; i < n; i++) as[i] = shf::Scalar::CreateRandom();
    const auto Car = shf::Commit(ck, as);
    shf::Scalar r = shf::Scalar::CreateRandom();
    const auto E = RandomizeAndDot(Es, as, pk, r);

    shf::Hash hp;
    shf::MultiExpP proof =
        shf::CreateProof(ck, pk, hp, {Es, E, Car.C}, as, Car.r, r);

    shf::Hash hv;
    REQUIRE(shf::VerifyProof(ck, pk, hv, {Es, E, Car.C}, proof));
  }
}
