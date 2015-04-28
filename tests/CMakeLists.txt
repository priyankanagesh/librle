INCLUDE_DIRECTORIES(include ${CMAKE_SOURCE_DIR}/include)
LINK_DIRECTORIES(${CMAKE_BINARY_DIR})

INCLUDE_DIRECTORIES(include)

SET(SRC_LIBRLE_TESTS
	test_rle_common.c
	test_rle_encap.c
	test_rle_frag.c
	test_rle_pack.c
	test_rle_decap.c)

ADD_LIBRARY(rle_tests EXCLUDE_FROM_ALL SHARED ${SRC_LIBRLE_TESTS})

ADD_EXECUTABLE(test_rle EXCLUDE_FROM_ALL test_rle.c)

TARGET_LINK_LIBRARIES(test_rle
	rle_tests rle pcap)

# By default, tests are not generated. You can either generate tests with:
# The RLE library test:
#   $ make test_rle
# Both of them:
#   $ make tests
ADD_TEST(test_rle test_rle)
ADD_CUSTOM_TARGET(tests DEPENDS test_rle)

# Definitions of the system commands for the next targets.
SET(SYS_CMD_GREP /bin/grep)
SET(SYS_CMD_ECHO /bin/echo)

# Check the tests with:
#   $ make check
SET(CMAKE_CTEST_COMMAND
       ${CMAKE_BINARY_DIR}/tests/test_rle
    |  ${SYS_CMD_GREP} --color=never -e "[Tt]est[s ].*[OK][OK]"
    && ${CMAKE_BINARY_DIR}/tests/test_rle > /dev/null
    || (${SYS_CMD_ECHO} "Test libRLE failed $$?" && exit 1))
ADD_CUSTOM_TARGET(check COMMAND ${CMAKE_CTEST_COMMAND} DEPENDS test_rle)
