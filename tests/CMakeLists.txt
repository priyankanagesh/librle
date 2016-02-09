INCLUDE_DIRECTORIES(include ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
LINK_DIRECTORIES(${CMAKE_BINARY_DIR})

SET(SRC_LIBRLE_TESTS
	test_rle_common.c
	test_rle_encap.c
	test_rle_encap_ctxtless.c
	test_rle_frag_ctxtless.c
	test_rle_frag.c
	test_rle_pack.c
	test_rle_decap.c
	test_rle_misc.c)

ADD_LIBRARY(rle_tests EXCLUDE_FROM_ALL SHARED ${SRC_LIBRLE_TESTS})

ADD_EXECUTABLE(test_rle EXCLUDE_FROM_ALL test_rle.c)
TARGET_LINK_LIBRARIES(test_rle rle_tests rle)

ADD_EXECUTABLE(test_non_regression EXCLUDE_FROM_ALL test_non_regression.c)
TARGET_LINK_LIBRARIES(test_non_regression rle pcap)

ADD_EXECUTABLE(test_non_regression_fpdu EXCLUDE_FROM_ALL test_non_regression_fpdu.c)
TARGET_LINK_LIBRARIES(test_non_regression_fpdu rle pcap)

ADD_EXECUTABLE(test_perfs EXCLUDE_FROM_ALL test_perfs.c)
TARGET_LINK_LIBRARIES(test_perfs rle pcap)

ADD_EXECUTABLE(test_perfs_fpdu EXCLUDE_FROM_ALL test_perfs_fpdu.c)
TARGET_LINK_LIBRARIES(test_perfs_fpdu rle pcap)

ADD_EXECUTABLE(test_dump_fpdus EXCLUDE_FROM_ALL test_dump_fpdus.c)
TARGET_LINK_LIBRARIES(test_dump_fpdus rle pcap)

# By default, tests are not generated. You can either generate tests with:
# The RLE library test:
#   $ make test_rle
# The non regression test:
#   $ make test_non_regression
# Both of them:
#   $ make tests
ADD_TEST(test_rle test_rle)
ADD_TEST(test_non_regression test_non_regression)
ADD_TEST(test_non_regression_fpdu test_non_regression_fpdu)
ADD_TEST(test_perfs test_perfs)
ADD_TEST(test_perfs_fpdu test_perfs_fpdu)
ADD_TEST(test_dump_fpdus test_dump_fpdus)
ADD_CUSTOM_TARGET(tests DEPENDS test_rle test_non_regression
	test_non_regression_fpdu test_dump_fpdus)

# Definitions of the system commands for the next targets.
SET(SYS_CMD_GREP grep)
SET(SYS_CMD_ECHO echo)
SET(SYS_CMD_RM rm)
SET(SYS_CMD_LCOV lcov)
SET(SYS_CMD_GENHTML genhtml)
SET(SYS_CMD_AFL_FUZZ afl-fuzz)

# Check the tests with:
#   $ make check
SET(CMAKE_CTEST_COMMAND
       ${CMAKE_BINARY_DIR}/tests/test_rle
    |  ${SYS_CMD_GREP} --color=never -e "[Tt]est[s ].*[OK][OK]"
    && ${CMAKE_BINARY_DIR}/tests/test_rle > /dev/null
    || (${SYS_CMD_ECHO} "Test libRLE failed $$?" && exit 1))
ADD_CUSTOM_TARGET(check COMMAND ${CMAKE_CTEST_COMMAND} DEPENDS test_rle)

# Static tests:
SET(CMAKE_CSTATIC_TESTS
       ${CMAKE_SOURCE_DIR}/tests/samples/scripts/test_static.sh ${CMAKE_BINARY_DIR}/tests/test_non_regression ${CMAKE_SOURCE_DIR}/tests/samples/fuzzing
    && ${CMAKE_SOURCE_DIR}/tests/samples/scripts/test_static.sh ${CMAKE_BINARY_DIR}/tests/test_non_regression ${CMAKE_SOURCE_DIR}/tests/samples/non_reg
    && ${CMAKE_SOURCE_DIR}/tests/samples/scripts/special_static_test.sh ${CMAKE_BINARY_DIR}/tests/test_non_regression ${CMAKE_SOURCE_DIR}/tests/samples/non_reg/error_burst_size_1.pcap f5)
ADD_CUSTOM_TARGET(static_tests COMMAND ${CMAKE_CSTATIC_TESTS} DEPENDS test_non_regression)

SET(CMAKE_CSTATIC_TESTS_FPDU
       ${CMAKE_SOURCE_DIR}/tests/samples/scripts/test_static.sh ${CMAKE_BINARY_DIR}/tests/test_non_regression_fpdu ${CMAKE_SOURCE_DIR}/tests/samples/fuzzing-fpdu
    && ${CMAKE_SOURCE_DIR}/tests/samples/scripts/test_static.sh ${CMAKE_BINARY_DIR}/tests/test_non_regression_fpdu ${CMAKE_SOURCE_DIR}/tests/samples/non_reg_fpdu)
   ADD_CUSTOM_TARGET(static_tests_fpdu COMMAND ${CMAKE_CSTATIC_TESTS_FPDU} DEPENDS test_non_regression_fpdu)

# If coverage is on.
# generate coverage files with:
#   $ make coverage
# generate coverage report with: (automatically generate coverage files)
#   $ make cov_report
IF (COVERAGE)
    SET(CMAKE_CCOVERAGE_COMMAND
           ${CMAKE_BINARY_DIR}/tests/test_rle > /dev/null
        && ${SYS_CMD_ECHO} "Coverage files generated in ${CMAKE_BINARY_DIR}/CMakeFiles/librle.dir/src")
    ADD_CUSTOM_TARGET(coverage DEPENDS test_rle COMMAND ${CMAKE_CCOVERAGE_COMMAND})
    SET(CMAKE_CCOV_REPORT_COMMAND
           ${SYS_CMD_LCOV} -c -d ${CMAKE_BINARY_DIR}/CMakeFiles/librle.dir/src -o coverage.run
        && ${SYS_CMD_GENHTML} -o ${CMAKE_BINARY_DIR}/html/ coverage.run
        && ${SYS_CMD_ECHO} "Coverage report: ${CMAKE_BINARY_DIR}/html/index.html" )
    ADD_CUSTOM_TARGET(cov_report DEPENDS coverage COMMAND ${CMAKE_CCOV_REPORT_COMMAND})
ENDIF(COVERAGE)

# If fuzzing is on, launch AFL fuzzing with:
#   $ make fuzzing (or $ make fuzzing-fpdu)
# /!\ You may be requiered to execute those commands as root before the fuzzing:
#   # echo core >/proc/sys/kernel/core_pattern
#   # cd /sys/devices/system/cpu
#   # echo performance | tee cpu*/cpufreq/scaling_governor
IF(FUZZING)
    SET(CMAKE_CFUZZING_COMMAND
           ${SYS_CMD_RM} -rf ${CMAKE_BINARY_DIR}/findings/
        && ${SYS_CMD_AFL_FUZZ} -i ${CMAKE_SOURCE_DIR}/tests/samples/fuzzing/ -o ${CMAKE_BINARY_DIR}/findings/ -m none ${CMAKE_BINARY_DIR}/tests/test_non_regression --ignore-malformed @@)
    ADD_CUSTOM_TARGET(fuzzing DEPENDS test_non_regression COMMAND ${CMAKE_CFUZZING_COMMAND})
    SET(CMAKE_CFUZZING_FPDU_COMMAND
           ${SYS_CMD_RM} -rf ${CMAKE_BINARY_DIR}/findings/
        && ${SYS_CMD_AFL_FUZZ} -i ${CMAKE_SOURCE_DIR}/tests/samples/fuzzing-fpdu/ -o ${CMAKE_BINARY_DIR}/findings/ -m none ${CMAKE_BINARY_DIR}/tests/test_non_regression_fpdu --ignore-malformed @@)
    ADD_CUSTOM_TARGET(fuzzing-fpdu DEPENDS test_non_regression_fpdu COMMAND ${CMAKE_CFUZZING_FPDU_COMMAND})
ENDIF(FUZZING)
