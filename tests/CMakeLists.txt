INCLUDE_DIRECTORIES(include ${CMAKE_SOURCE_DIR}/include)
LINK_DIRECTORIES(${CMAKE_BINARY_DIR})

INCLUDE_DIRECTORIES(include)

SET(SRC_LIBRLE_TESTS
	test_rle_common.c
	test_rle_encap.c
	test_rle_frag.c
	test_rle_pack.c
	test_rle_decap.c)

ADD_LIBRARY(rle_tests SHARED ${SRC_LIBRLE_TESTS})

ADD_EXECUTABLE(test_rle test_rle.c)

TARGET_LINK_LIBRARIES(test_rle
	rle_tests rle)

