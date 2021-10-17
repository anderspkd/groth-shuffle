#ifndef SHF_CIPHER_H
#define SHF_CIPHER_H

#include <vector>

#include "curve.h"

namespace shf {

struct Ctxt {
  Point U;
  Point V;
};

using SecretKey = Scalar;
using PublicKey = Point;

SecretKey CreateSecretKey();
PublicKey CreatePublicKey(const SecretKey& sk);

/**
 * @brief Encrypt a message using provided randomness.
 * @param pk the public key
 * @param m the message
 * @param r randomness
 * @return a fresh encryption of m.
 */
Ctxt Encrypt(const PublicKey& pk, const Point& m, const Scalar& r);

/**
 * @brief Encrypt a message
 * @param pk the public key
 * @param m the message
 * @return a fresh encryption m
 */
Ctxt Encrypt(const PublicKey& pk, const Point& m);

/**
 * @brief Decrypt an encrypted message.
 * @param sk the decryption key
 * @param ctxt the ciphertext
 * @return the plaintext
 */
Point Decrypt(const SecretKey& sk, const Ctxt& ctxt);

/**
 * @brief Multiply a scalar unto a ciphertext
 * @param s the scalar
 * @param E an encryption of some message <code>m</code>
 * @return an encryption of <code>s*m</code>.
 */
Ctxt Multiply(const Scalar& s, const Ctxt& E);

/**
 * @brief Homomorphically add two ciphertexts.
 * @param E0 the first ciphertext. An encryption of <code>m1</code>
 * @param E1 the second ciphertext. An encryption of <code>m2</code>
 * @return an encryption of <code>m1 + m2</code>.
 */
Ctxt Add(const Ctxt& E0, const Ctxt& E1);

/**
 * @brief Compute a "dot" product between a list of ciphertexts and scalars.
 * @param as the scalars
 * @param Es the ciphertexts
 * @return a ciphertext E defined as E = sum_i as[i]*Es[i].
 */
Ctxt Dot(const std::vector<shf::Scalar>& as, const std::vector<Ctxt>& Es);

}  // namespace mh

#endif  // SHF_CIPHER_H
