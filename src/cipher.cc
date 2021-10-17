#include "cipher.h"

shf::SecretKey shf::CreateSecretKey() { return shf::Scalar::CreateRandom(); }

shf::PublicKey shf::CreatePublicKey(const shf::SecretKey& sk) {
  return shf::Point::Generator() * sk;
}

shf::Ctxt shf::Encrypt(const shf::PublicKey& pk, const shf::Point& m,
                     const shf::Scalar& r) {
  const auto U = shf::Point::Generator() * r;
  return {U, m + r * pk};
}

shf::Ctxt shf::Encrypt(const shf::PublicKey& pk, const shf::Point& m) {
  return Encrypt(pk, m, shf::Scalar::CreateRandom());
}

shf::Point shf::Decrypt(const shf::SecretKey& sk, const shf::Ctxt& ctxt) {
  return ctxt.V - sk * ctxt.U;
}

shf::Ctxt shf::Add(const shf::Ctxt& E0, const shf::Ctxt& E1) {
  return {E0.U + E1.U, E0.V + E1.V};
}

shf::Ctxt shf::Multiply(const shf::Scalar& s, const shf::Ctxt& E) {
  return {s * E.U, s * E.V};
}

shf::Ctxt shf::Dot(const std::vector<shf::Scalar>& as,
                 const std::vector<shf::Ctxt>& Es) {
  shf::Ctxt E = shf::Multiply(as[0], Es[0]);
  const auto n = as.size();
  for (std::size_t i = 1; i < n; ++i)
    E = shf::Add(E, shf::Multiply(as[i], Es[i]));
  return E;
}
