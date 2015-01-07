INCLUDE_DIRECTORIES(include ${CMAKE_SOURCE_DIR}/include)
LINK_DIRECTORIES(${CMAKE_BINARY_DIR})

SET(CMAKE_C_FLAGS "-g -O2 -Wall")

ADD_EXECUTABLE(test_rle_encap_deencap test_common.c test_rle_encap_deencap.c)

ADD_EXECUTABLE(test_rle_frag_rea test_common.c test_rle_frag_rea.c)

ADD_EXECUTABLE(test_rle_frag_rea_min_max test_common.c test_rle_frag_rea_min_max.c)

TARGET_LINK_LIBRARIES(test_rle_encap_deencap
	rle pcap)

TARGET_LINK_LIBRARIES(test_rle_frag_rea
	rle pcap)

TARGET_LINK_LIBRARIES(test_rle_frag_rea_min_max
	rle pcap)

