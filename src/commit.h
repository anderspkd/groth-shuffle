#ifndef MH_COMMIT_H
#define MH_COMMIT_H

#include <vector>

#include "curve.h"

namespace shf {

struct CommitKey {
  std::vector<Point> G;
  Point H;

  std::size_t Size() const { return G.size(); };
};

CommitKey CreateCommitKey(const std::size_t size);

struct CommitmentAndRandomness {
  Point C;
  Scalar r;
};

CommitmentAndRandomness Commit(const CommitKey& ck,
                               const std::vector<Scalar>& m);

Point Commit(const CommitKey& ck, const Scalar& r,
             const std::vector<Scalar>& m);

bool CheckCommitment(const CommitKey& ck, const Point& comm, const Scalar& r,
                     const std::vector<Scalar>& m);

}  // namespace mh

#endif  // MH_COMMIT_H
