#include "zkp.h"

#include <iostream>

static inline shf::Scalar DLogChallenge(shf::Hash& hash, const shf::Point& p0,
                                       const shf::Point& p1,
                                       const shf::Point& p2) {
  hash.Update(p0).Update(p1).Update(p2);
  return ScalarFromHash(hash);
}

shf::DLogP shf::CreateProof(const shf::DLogS& statement, shf::Hash& hash,
                          const shf::Scalar& w) {
  const Point B = statement.B;
  const Point P = statement.P;
  const Scalar v = Scalar::CreateRandom();
  const Point T = v * B;
  const Scalar c = DLogChallenge(hash, B, P, T);
  const Scalar r = v - c * w;
  return {T, r};
}

bool shf::VerifyProof(const shf::DLogS& statement, shf::Hash& hash,
                     const shf::DLogP& proof) {
  const Point T = proof.T;
  const Scalar r = proof.r;
  const Point B = statement.B;
  const Point P = statement.P;
  const Scalar c = DLogChallenge(hash, B, P, T);
  const Point cP = c * P;
  const Point rB = r * B;
  return cP + rB == T;
}

static inline shf::Scalar DLogEqChallenge(shf::Hash& hash, const shf::Point& p0,
                                         const shf::Point& p1,
                                         const shf::Point& p2,
                                         const shf::Point& p3,
                                         const shf::Point& p4,
                                         const shf::Point& p5) {
  hash.Update(p0).Update(p1).Update(p2).Update(p3).Update(p4).Update(p5);
  return ScalarFromHash(hash);
}

shf::DLogEqP shf::CreateProof(const shf::DLogEqS& statement, shf::Hash& hash,
                            const shf::Scalar& w) {
  const Point G = statement.G;
  const Point A = statement.A;
  const Point H = statement.H;
  const Point B = statement.B;
  const Scalar v = Scalar::CreateRandom();
  const Point T = v * G;
  const Point K = v * H;
  const Scalar c = DLogEqChallenge(hash, G, A, H, B, T, K);
  const Scalar r = v - c * w;
  return {T, K, r};
}

bool shf::VerifyProof(const shf::DLogEqS& statement, shf::Hash& hash,
                     const shf::DLogEqP& proof) {
  const Point G = statement.G;
  const Point A = statement.A;
  const Point H = statement.H;
  const Point B = statement.B;
  const Point T = proof.T;
  const Point K = proof.K;
  const Scalar r = proof.r;
  const Scalar c = DLogEqChallenge(hash, G, A, H, B, T, K);
  const Point cA = c * A;
  const Point cB = c * B;
  const Point rG = r * G;
  const Point rH = r * H;
  return rG == T - cA && rH == K - cB;
}

// create a vector and reserve a size
#define SCALAR_VECTOR(_name, _size) \
  std::vector<shf::Scalar> _name;    \
  _name.reserve(_size);

static inline shf::Scalar ProductChallenge(shf::Hash& hash, const shf::Point& C0,
                                          const shf::Point& C1,
                                          const shf::Point& C2) {
  hash.Update(C0).Update(C1).Update(C2);
  return shf::ScalarFromHash(hash);
}

shf::ProductP shf::CreateProof(const shf::CommitKey& ck, shf::Hash& hash,
                             const shf::ProductS& statement,
                             const std::vector<shf::Scalar>& w0,
                             const shf::Scalar& w1) {
  const auto n = w0.size();
  const auto C = statement.C;
  const auto b = statement.b;

  SCALAR_VECTOR(ds, n);
  SCALAR_VECTOR(bs, n);
  SCALAR_VECTOR(es, n);

  bs.emplace_back(w0[0]);
  for (std::size_t i = 0; i < n; ++i) {
    ds.emplace_back(Scalar::CreateRandom());
    es.emplace_back(Scalar::CreateRandom());
    if (i == 0) continue;
    bs.emplace_back(w0[i] * bs[i - 1]);
  }
  es[0] = ds[0];
  es[n - 1] = Scalar();

  SCALAR_VECTOR(sd, n - 1);
  SCALAR_VECTOR(bd, n - 1);

  for (std::size_t i = 0; i < n - 1; ++i) {
    sd.emplace_back(-es[i] * ds[i + 1]);
    bd.emplace_back(es[i + 1] - w0[i + 1] * es[i] - bs[i] * ds[i + 1]);
  }

  const auto Cr0 = Commit(ck, ds);
  const auto Cr1 = Commit(ck, sd);
  const auto Cr2 = Commit(ck, bd);

  const auto c = ProductChallenge(hash, Cr0.C, Cr1.C, Cr2.C);

  SCALAR_VECTOR(aa, n);
  SCALAR_VECTOR(bb, n);

  for (std::size_t i = 0; i < n; ++i) {
    aa.emplace_back(c * w0[i] + ds[i]);
    bb.emplace_back(c * bs[i] + es[i]);
  }

  const auto r = c * w1 + Cr0.r;
  const auto s = c * Cr2.r + Cr1.r;

  return {Cr0.C, Cr1.C, Cr2.C, aa, bb, r, s};
}

bool shf::VerifyProof(const shf::CommitKey& ck, shf::Hash& hash,
                     const shf::ProductS& statement, const shf::ProductP& proof) {
  const auto C0 = proof.C0;
  const auto C1 = proof.C1;
  const auto C2 = proof.C2;

  const auto c = ProductChallenge(hash, C0, C1, C2);

  const auto C = statement.C;
  const auto lhs0 = c * C + C0;
  const auto lhs1 = c * C2 + C1;

  Point rhs0, rhs1;
  std::size_t i = 0;
  const auto as = proof.as;
  const auto bs = proof.bs;
  const auto b = statement.b;
  for (; i < as.size() - 2; ++i) {
    const auto Gi = ck.G[i];
    rhs0 += Gi * as[i];
    rhs1 += Gi * (c * bs[i + 1] - bs[i] * as[i + 1]);
  }
  rhs0 += ck.G[i] * as[i];
  rhs1 += ck.G[i] * (c * c * b - bs[i] * as[i + 1]);
  i++;
  rhs0 += ck.G[i] * as[i];

  const auto r = proof.r;
  const auto s = proof.s;

  return lhs0 == rhs0 + ck.H * r && lhs1 == rhs1 + ck.H * s;
}

static inline shf::CommitmentAndRandomness CommitOne(const shf::CommitKey& ck,
                                                    const shf::Scalar& m) {
  const auto r = shf::Scalar::CreateRandom();
  return {m * ck.G[0] + r * ck.H, r};
}

static inline void HashStatement(shf::Hash& hash,
                                 const shf::MultiExpS& statement) {
  const auto Es = statement.Es;
  const auto E = statement.E;
  const auto C = statement.C;
  hash.Update(E.U).Update(E.V).Update(C);
  for (const auto& ctxt : Es) hash.Update(ctxt.U).Update(ctxt.V);
}

static inline shf::Scalar MultiExpChallenge(shf::Hash& hash,
                                           const shf::MultiExpS& statement,
                                           const shf::Point& C0,
                                           const shf::Point& C1,
                                           const shf::Ctxt& E) {
  HashStatement(hash, statement);
  hash.Update(C0).Update(C1).Update(E.U).Update(E.V);
  return shf::ScalarFromHash(hash);
}

static inline std::vector<shf::Scalar> MulAndSum(
    const std::vector<shf::Scalar>& a, const std::vector<shf::Scalar>& b,
    const shf::Scalar& x) {
  const auto n = a.size();
  SCALAR_VECTOR(c, n);
  for (std::size_t i = 0; i < n; ++i) c.emplace_back(a[i] + b[i] * x);
  return c;
}

shf::MultiExpP shf::CreateProof(const shf::CommitKey& ck, const shf::PublicKey& pk,
                              shf::Hash& hash, const shf::MultiExpS& statement,
                              const std::vector<shf::Scalar>& w0,
                              const shf::Scalar& w1, const shf::Scalar& w2) {
  const std::size_t n = w0.size();
  const std::vector<Ctxt> Es = statement.Es;
  const Ctxt E = statement.E;
  const Point C = statement.C;

  SCALAR_VECTOR(a0, n);
  for (std::size_t i = 0; i < n; ++i) a0.emplace_back(Scalar::CreateRandom());

  const CommitmentAndRandomness Cr0 = Commit(ck, a0);

  const Scalar b = Scalar::CreateRandom();
  const CommitmentAndRandomness Crb = CommitOne(ck, b);

  const Scalar t = Scalar::CreateRandom();
  const Point bG = b * Point::Generator();
  const Ctxt E0 = shf::Add(shf::Encrypt(pk, bG, t), shf::Dot(a0, Es));

  const Scalar c = MultiExpChallenge(hash, statement, Cr0.C, Crb.C, E0);

  const std::vector<Scalar> aa = MulAndSum(a0, w0, c);
  const Scalar rr = Cr0.r + w1 * c;
  const Scalar tt = t + w2 * c;

  return {Cr0.C, Crb.C, E0, aa, rr, b, Crb.r, tt};
}

static inline bool CtxtEqual(const shf::Ctxt& E0, const shf::Ctxt& E1) {
  return E0.U == E1.U && E0.V == E1.V;
}

bool shf::VerifyProof(const shf::CommitKey& ck, const shf::PublicKey& pk,
                     shf::Hash& hash, const shf::MultiExpS& statement,
                     const shf::MultiExpP& proof) {
  const auto c =
      MultiExpChallenge(hash, statement, proof.C0, proof.C1, proof.E);

  const Point C = proof.C0 + c * statement.C;
  // E0 = E + c*E
  // E1 = Enc(pk, 1, t) + Es^a
  const Ctxt E0 = Add(proof.E, Multiply(c, statement.E));
  const Ctxt E1 = Add(Encrypt(pk, Point::Generator() * proof.b, proof.t),
                      Dot(proof.a, statement.Es));

  return C == Commit(ck, proof.r, proof.a) && CtxtEqual(E0, E1);
}
