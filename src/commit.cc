#include "commit.h"

#include <stdexcept>

shf::CommitKey shf::CreateCommitKey(const std::size_t size) {
  if (size == 0) throw std::invalid_argument("cannot create a key of size 0");

  CommitKey ck;
  ck.G.reserve(size);
  ck.H = Point::CreateRandom();
  for (std::size_t i = 0; i < size; ++i)
    ck.G.emplace_back(Point::CreateRandom());
  return ck;
}

shf::Point shf::Commit(const shf::CommitKey& ck, const shf::Scalar& r,
                     const std::vector<shf::Scalar>& m) {
  const std::size_t n = m.size();
  Point C;
  for (std::size_t i = 0; i < n; ++i) C += m[i] * ck.G[i];
  return C + r * ck.H;
}

shf::CommitmentAndRandomness shf::Commit(const shf::CommitKey& ck,
                                       const std::vector<shf::Scalar>& m) {
  const auto r = Scalar::CreateRandom();
  const auto C = Commit(ck, r, m);
  return {C, r};
}

bool shf::CheckCommitment(const shf::CommitKey& ck, const shf::Point& comm,
                         const shf::Scalar& r,
                         const std::vector<shf::Scalar>& m) {
  const auto comm_ = Commit(ck, r, m);
  return comm_ == comm;
}
