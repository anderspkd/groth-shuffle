cmake_minimum_required( VERSION 3.10 )

project( shuffle 
  VERSION 0.1
  DESCRIPTION "simple implementation of a cryptographic Shuffle" )

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS
  "${CMAKE_CXX_FLAGS} -march=native -Wall -Wextra -pedantic -Werror")

set(RELIC_LIB "${CMAKE_SOURCE_DIR}/thirdparty/lib/librelic_s.a")

set(SOURCE_FILES
    src/cipher.cc
    src/commit.cc
    src/curve.cc
    src/hash.cc
    src/prg.cc
    src/shuffler.cc
    src/zkp.cc)

set(TEST_SOURCE_FILES
    test/test_main.cc
    test/test_curve.cc
    test/test_hash.cc
    test/test_zkp.cc
    test/test_shuffler.cc)

include_directories(src)
include_directories(thirdparty)

set(TEST_EXEC tests.x)

set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -g" )
add_compile_definitions( TEST_DATA_DIR="${CMAKE_SOURCE_DIR}/test/data/" )
find_package( Catch2 REQUIRED )
include( CTest )
include( Catch )
add_executable( ${TEST_EXEC} ${SOURCE_FILES} ${TEST_SOURCE_FILES} )
target_link_libraries( ${TEST_EXEC}
  Catch2::Catch2
  ${RELIC_LIB}
  gmp
  pthread )
catch_discover_tests( ${TEST_EXEC} )
