#ifndef SHF_ZKP_H
#define SHF_ZKP_H

#include <vector>

#include "cipher.h"
#include "commit.h"
#include "curve.h"
#include "hash.h"

namespace shf {

/**
 * @brief Knowledge of discrete log.
 *
 * A DLogS statement (B, P) is of the form "I know x such that xB == P".
 */
struct DLogS {
  Point B;
  Point P;
};

/**
 * @brief Proof for a DLog statement. See DLogS.
 */
struct DLogP {
  Point T;
  Scalar r;
};

/**
 * @brief Create a proof of knowledge of a discrete log
 * @param statement the proof statement
 * @param hash a hash function object
 * @param w the witness
 * @return a new proof.
 */
DLogP CreateProof(const DLogS& statement, Hash& hash, const Scalar& w);

/**
 * @brief Verify a proof of knowledge of discrete logarithm.
 * @param statement the proof statement
 * @param hash a hash function object
 * @param proof the proof to verify
 * @return true if the proof is valid and false otherwise.
 */
bool VerifyProof(const DLogS& statement, Hash& hash, const DLogP& proof);

/**
 * @brief Knowledge of equality of discrete log.
 *
 * A DLogEqS statement (G, A, H, B) is one of the form
 * "I know x such that xG == A and xH == B"
 */
struct DLogEqS {
  Point G;
  Point A;
  Point H;
  Point B;
};

/**
 * @brief Proof a equality of DLogs statement. See DLogEqS.
 */
struct DLogEqP {
  Point T;
  Point K;
  Scalar r;
};

/**
 * @brief Create a proof of equality of discrete logs.
 * @param statement the proof statement
 * @param hash a hash function object
 * @param w the witness
 * @return a proof.
 */
DLogEqP CreateProof(const DLogEqS& statement, Hash& hash, const Scalar& w);

/**
 * @brief Verify a proof of equality of discrete logs.
 * @param statement the proof statement
 * @param hash a hash function object
 * @param proof the proof to verify
 * @return true if the proof is valid and false otherwise.
 */
bool VerifyProof(const DLogEqS& statement, Hash& hash, const DLogEqP& proof);

/*
 * The next part of the header contains definitions of the sub-proofs needed to
 * construct proofs of correctness a shuffle. These two proofs are
 *
 * 1. Proof that a vector of committed values have a specific product
 * 2. Proof that a ciphertext is a specific linear combination of other
 *    ciphertexts
 *
 * The first proof demonstrates knowledge of values a_1 ... a_n, r such that
 *
 *   b = a_1 * ... * a_n and C = Comm(ck ; a_1, ..., a_n ; r)
 *
 * In other words, that the values contained in a commitment multiply to a
 * specific value, and that we know the opening of said commitment.
 *
 * The second proof demonstrates knowledge of values r, x, a_1, ..., a_n, such
 * that
 *
 *   E = Enc(pk ; 1 ; x) + (a_1 * E_i + ... + a_n * E_n) and
 *   C = Comm(ck ; a_1, ..., a_n ; r)
 *
 * for some ciphertexts E, E_1, ..., E_n.
 */

struct ProductS {
  Point C;
  Scalar b;
};

struct ProductP {
  Point C0;
  Point C1;
  Point C2;
  std::vector<Scalar> as;
  std::vector<Scalar> bs;
  Scalar r;
  Scalar s;
};

/**
 * @brief Create a proof of a committed product.
 * @param ck a commitment key
 * @param hash a hash function object
 * @param statement the statement
 * @param w0 witness (messages that are in the commitment)
 * @param w1 witness (randomness used for commitment)
 * @return a proof.
 */
ProductP CreateProof(const CommitKey& ck, Hash& hash, const ProductS& statement,
                     const std::vector<Scalar>& w0, const Scalar& w1);

/**
 * @brief Verify a product proof.
 * @param ck a commitment key
 * @param hash a hash function object
 * @param statement the statement
 * @param proof the proof to verify
 * @return true if the proof is valid and false otherwise.
 */
bool VerifyProof(const CommitKey& ck, Hash& hash, const ProductS& statement,
                 const ProductP& proof);

struct MultiExpS {
  std::vector<Ctxt> Es;
  Ctxt E;
  Point C;
};

struct MultiExpP {
  Point C0;
  Point C1;
  Ctxt E;
  std::vector<Scalar> a;
  Scalar r;
  Scalar b;
  Scalar s;
  Scalar t;
};

/**
 * @brief Create a proof that a ciphertext satisfies a certain function.
 * @param ck a commit key
 * @param pk a public key
 * @param hash a hash function object
 * @param statement the statement
 * @param w0 witness (messages in a commitment)
 * @param w1 witness (randomness for a commitment)
 * @param w2 witness (randomness for an encryption of 1)
 * @return a proof.
 */
MultiExpP CreateProof(const CommitKey& ck, const PublicKey& pk, Hash& hash,
                      const MultiExpS& statement, const std::vector<Scalar>& w0,
                      const Scalar& w1, const Scalar& w2);

/**
 * @brief Verify a multi exponent proof.
 * @param ck a commit key
 * @param pk a public key
 * @param hash a hash function object
 * @param statement a statement
 * @param proof the proof to verify
 * @return true if the proof is valid and false otherwise.
 */
bool VerifyProof(const CommitKey& ck, const PublicKey& pk, Hash& hash,
                 const MultiExpS& statement, const MultiExpP& proof);

}  // namespace mh

#endif  // SHF_ZKP_H
