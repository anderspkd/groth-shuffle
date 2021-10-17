#include "shuffler.h"

#include <iostream>
#include <numeric>

shf::Permutation shf::CreatePermutation(std::size_t size, shf::Prg& prg) {
  if (!size) return Permutation();

  Permutation p(size);
  std::iota(p.begin(), p.end(), 0);
  std::vector<std::size_t> r(size);
  prg.Fill(r);

  // Fisher-Yates
  std::size_t c = 0;
  for (int i = size - 1; i >= 0; i--) {
    std::size_t j = r[c++] % (i + 1);
    std::swap(p[i], p[j]);
  }

  return p;
}

static inline std::vector<shf::Scalar> PermutationAsScalars(
    const shf::Permutation p) {
  std::vector<shf::Scalar> s;
  const std::size_t n = p.size();
  s.reserve(n);
  for (std::size_t i = 0; i < n; ++i)
    s.emplace_back(shf::Scalar::CreateFromInt(p[i]));
  return s;
}

// Compute {x, x^2, x^3, ..., x^n}
static inline std::vector<shf::Scalar> ExpSuccessive(const shf::Scalar& x,
                                                    const std::size_t n) {
  std::vector<shf::Scalar> values;
  values.reserve(n);
  values.emplace_back(x);
  for (std::size_t i = 1; i < n; ++i) values.emplace_back(values[i - 1] * x);
  return values;
}

#define TYPED_VECTOR(_typ, _name, _size) \
  std::vector<_typ> _name;               \
  _name.reserve(_size);

#define SCALAR_VECTOR(_name, _size) TYPED_VECTOR(shf::Scalar, _name, _size)

static inline shf::Ctxt Randomize(const shf::PublicKey& pk, const shf::Ctxt& E,
                                 const shf::Scalar& r) {
  return shf::Add(shf::Encrypt(pk, shf::Point(), r), E);
}

static inline std::vector<shf::Ctxt> Randomize(
    const shf::PublicKey& pk, const std::vector<shf::Ctxt>& Es,
    const std::vector<shf::Scalar>& rs) {
  const std::size_t n = Es.size();
  TYPED_VECTOR(shf::Ctxt, randomized, n);
  const shf::Point one = shf::Point();
  for (std::size_t i = 0; i < n; ++i) {
    randomized.emplace_back(Randomize(pk, Es[i], rs[i]));
  }
  return randomized;
}

static inline shf::Scalar NegateInnerProd(const std::vector<shf::Scalar>& a,
                                         const std::vector<shf::Scalar>& b) {
  shf::Scalar d;
  for (std::size_t i = 0; i < a.size(); i++) d += a[i] * b[i];
  return -d;
}

static inline shf::Scalar ShuffleChallenge1(shf::Hash& hash,
                                           const std::vector<shf::Ctxt>& Es,
                                           const std::vector<shf::Ctxt>& pEs,
                                           const shf::Point& C) {
  for (const shf::Ctxt& E : Es) hash.Update(E.U).Update(E.V);
  for (const shf::Ctxt& E : pEs) hash.Update(E.U).Update(E.V);
  hash.Update(C);
  return shf::ScalarFromHash(hash);
}

#define RANDOM_SCALAR_VECTOR(_name, _size)            \
  do {                                                \
    _name.reserve(_size);                             \
    for (std::size_t __i = 0; __i < _size; ++__i)     \
      _name.emplace_back(shf::Scalar::CreateRandom()); \
  } while (0)

static inline shf::Scalar ShuffleChallenge2(shf::Hash& hash, const shf::Scalar& c,
                                           const shf::Point& C) {
  hash.Update(c).Update(C);
  return shf::ScalarFromHash(hash);
}

static inline shf::Scalar ShuffleChallenge3(shf::Hash& hash,
                                           const shf::Scalar& c) {
  hash.Update(c);
  return shf::ScalarFromHash(hash);
}

shf::ShuffleP shf::Shuffler::Shuffle(const std::vector<shf::Ctxt>& Es,
                                   shf::Hash& hash) {
  const std::size_t n = Es.size();

  // permute and randomize ciphertexts
  const Permutation p = CreatePermutation(n, m_prg);
  std::vector<Scalar> rho;
  RANDOM_SCALAR_VECTOR(rho, n);
  const std::vector<Ctxt> pEs = Randomize(m_pk, Permute(Es, p), rho);

  // Ca = commit(ck ; pi(1) ... pi(n) ; r)
  const std::vector<Scalar> a = PermutationAsScalars(p);
  const CommitmentAndRandomness Ca = Commit(m_ck, a);

  const Scalar x = ShuffleChallenge1(hash, Es, pEs, Ca.C);

  // Cb = commit(ck ; pi(1)*c0 ... pi(n)*c0 ; s);
  const std::vector<Scalar> xexp = ExpSuccessive(x, n);
  const std::vector<Scalar> b = Permute(xexp, p);
  const CommitmentAndRandomness Cb = Commit(m_ck, b);

  const Scalar y = ShuffleChallenge2(hash, x, Cb.C);
  const Scalar z = ShuffleChallenge3(hash, y);

  SCALAR_VECTOR(dz, n);
  dz.emplace_back(y * a[0] + b[0] - z);
  Scalar prod = dz[0];
  for (std::size_t i = 1; i < n; ++i) {
    dz.emplace_back(y * a[i] + b[i] - z);
    prod *= dz[i];
  }
  const Scalar t = y * Ca.r + Cb.r;
  const Point CdCz = Commit(m_ck, t, dz);
  // product proof that commit(ck ; d - z ; t) is a commitment of dz.
  const ProductP proof0 = CreateProof(m_ck, hash, {CdCz, prod}, dz, t);

  const Scalar rr = NegateInnerProd(rho, b);
  const Ctxt Ex = Add(Encrypt(m_pk, Point(), rr), Dot(b, pEs));
  const MultiExpP proof1 =
      CreateProof(m_ck, m_pk, hash, {pEs, Ex, Cb.C}, b, Cb.r, rr);

  return {pEs, Ca.C, Cb.C, proof0, proof1};
}

static inline shf::Point CommitConstantNoRandomness(const shf::CommitKey& ck,
                                                   const shf::Scalar& s) {
  shf::Point Cz;
  for (const shf::Point& Gi : ck.G) Cz += Gi * s;
  return Cz;
}

bool shf::Shuffler::VerifyShuffle(const std::vector<shf::Ctxt>& ctxts,
                                 const shf::ShuffleP& proof, shf::Hash& hash) {
  const Scalar x = ShuffleChallenge1(hash, ctxts, proof.permuted, proof.Ca);
  const Scalar y = ShuffleChallenge2(hash, x, proof.Cb);
  const Scalar z = ShuffleChallenge3(hash, y);

  const Point Cz = CommitConstantNoRandomness(m_ck, -z);
  const Point Cd = y * proof.Ca + proof.Cb;
  const Point CdCz = Cd + Cz;

  const std::size_t n = ctxts.size();
  SCALAR_VECTOR(xexp, n);
  xexp.emplace_back(x);
  Scalar prod = x - z;
  for (std::size_t i = 1; i < n; ++i) {
    xexp.emplace_back(xexp[i - 1] * x);
    prod *= Scalar::CreateFromInt(i) * y + xexp[i] - z;
  }

  const ProductP proof0 = proof.product_proof;
  const bool check0 = VerifyProof(m_ck, hash, {CdCz, prod}, proof0);

  const std::vector<Ctxt> pEs = proof.permuted;
  const Ctxt Ex = Dot(xexp, ctxts);
  const MultiExpP proof1 = proof.multiexp_proof;
  const bool check1 =
      VerifyProof(m_ck, m_pk, hash, {pEs, Ex, proof.Cb}, proof1);

  return check0 && check1;
}
