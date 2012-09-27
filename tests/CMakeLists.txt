INCLUDE_DIRECTORIES(include ../include)
LINK_DIRECTORIES(../../build)

SET(CMAKE_C_FLAGS "-g -Wall")

ADD_EXECUTABLE(test_rle_encap_deencap test_rle_encap_deencap.c)

ADD_EXECUTABLE(test_rle_frag_rea test_rle_frag_rea.c)

ADD_EXECUTABLE(test_rle_frag_rea_min_max test_rle_frag_rea_min_max.c)

TARGET_LINK_LIBRARIES(test_rle_encap_deencap
	rle pcap)

TARGET_LINK_LIBRARIES(test_rle_frag_rea
	rle pcap)

TARGET_LINK_LIBRARIES(test_rle_frag_rea_min_max
	rle pcap)

