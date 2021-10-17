#ifndef SHF_SHUFFLER_H
#define SHF_SHUFFLER_H

#include <stdexcept>
#include <vector>

#include "cipher.h"
#include "commit.h"
#include "curve.h"
#include "prg.h"
#include "zkp.h"

namespace shf {

/**
 * @brief A permutation is a list of integers.
 */
using Permutation = std::vector<std::size_t>;

/**
 * @brief Create a random permutation of a given size.
 * @param size the size of the permutation
 * @param prg the random generator to use
 * @return a random permutation.
 */
Permutation CreatePermutation(std::size_t size, shf::Prg& prg);

/**
 * @brief Permute a list of things.
 * @param things the list of things to permute
 * @param perm the permutation to use
 * @return a permutation of the input.
 */
template <typename T>
std::vector<T> Permute(const std::vector<T>& things, const Permutation& perm) {
  const std::size_t n = things.size();
  if (n != perm.size()) throw std::invalid_argument("invalid permutation size");

  std::vector<T> permuted;
  permuted.reserve(n);
  for (const auto& idx : perm) permuted.emplace_back(things[idx]);
  return permuted;
}

struct ShuffleP {
  std::vector<Ctxt> permuted;
  Point Ca;
  Point Cb;
  ProductP product_proof;
  MultiExpP multiexp_proof;
};

class Shuffler {
 public:
  Shuffler(const PublicKey& pk, const CommitKey& ck, Prg& prg)
      : m_pk(pk), m_ck(ck), m_prg(prg){};

  /**
   * @brief Shuffle a set of ciphertexts and return a proof of correctness.
   * @param ctxts ciphertexts to shuffle
   * @param hash a hash function object
   * @return a proof of that the shuffle was done correctly.
   */
  ShuffleP Shuffle(const std::vector<Ctxt>& ctxts, Hash& hash);

  /**
   * @brief Verify a shuffle.
   * @param ctxts the ciphertexts that were shuffled
   * @param proof the proof to verify
   * @param hash a hash function object
   * @return true if the shuffle was correct and false otherwise.
   */
  bool VerifyShuffle(const std::vector<Ctxt>& ctxts, const ShuffleP& proof,
                     Hash& hash);

 private:
  PublicKey m_pk;
  CommitKey m_ck;
  Prg m_prg;
};

}  // namespace mh

#endif  // SHF_SHUFFLER_H
