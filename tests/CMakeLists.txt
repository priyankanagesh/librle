INCLUDE_DIRECTORIES(include ${CMAKE_SOURCE_DIR}/include)
LINK_DIRECTORIES(${CMAKE_BINARY_DIR})

INCLUDE_DIRECTORIES(include)

SET(SRC_LIBRLE_TEST
	test_common.c
	test_rle_encap_deencap.c
	test_rle_frag_rea.c
	test_rle_frag_rea_min_max.c)

ADD_LIBRARY(rle_test SHARED ${SRC_LIBRLE_TEST})

ADD_EXECUTABLE(test_rle test_main.c)

TARGET_LINK_LIBRARIES(test_rle
	rle rle_test pcap)

