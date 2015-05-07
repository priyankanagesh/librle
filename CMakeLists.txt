PROJECT(librle C)

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
INCLUDE(${INFRA_PREFIX}deps/infra/cmake/a9780.cmake)

# Options
#
OPTION(BUILD_TESTS "Build simple tests" ON)
OPTION(BUILD_DOC "Build documentation" ON)
OPTION(TIME_DEBUG "Print encapsulation and deencapsulation durations" OFF)
OPTION(COVERAGE "Allow code coverage. (requires GCOV. Optionnaly LCOV and genhtml for reports)" OFF)
OPTION(FUZZING "Instrumentation for fuzzing with AFL and ASAN. (requires AFL and ASAN)" OFF)

INCLUDE_DIRECTORIES(include)

SET(PACKAGE_NAME librle)
SET(DESCRIPTION_SUMMARY "Return Link Encapsulation library")
SET(TARGET_NAME rle)

SET(ABI_VERSION_MAJOR "1")
SET(ABI_VERSION_MINOR "0")
SET(ABI_VERSION_PATCH "0")
SET(ABI_VERSION "${ABI_VERSION_MAJOR}.${ABI_VERSION_MINOR}.${ABI_VERSION_PATCH}")

SET(SRC_LIBRLE
	src/crc.c
	src/deencap.c
	src/encap.c
	src/fragmentation.c
	src/reassembly.c
	src/rle_ctx.c
	src/rle_transmitter.c
	src/rle_receiver.c
	src/rle_conf.c
    src/rle_header_proto_type_field.c
    src/rle.c
)

add_definitions("-g -W -Wall -Wextra -Wuninitialized
-Wstrict-prototypes -Wcast-align -Wmissing-prototypes -Wchar-subscripts
-Wpointer-arith -Winline  -Wno-conversion -Wshadow -fno-strict-aliasing")

ADD_LIBRARY(rle SHARED ${SRC_LIBRLE})

TARGET_LINK_LIBRARIES(rle
	pthread
)
SET_TARGET_PROPERTIES(rle PROPERTIES SOVERSION ${ABI_VERSION_MAJOR} VERSION ${ABI_VERSION})

IF (FUZZING)
    set(ENV{AFL_USE_ASAN} 1)
    set(ENV{AFL_HARDEN} 1)
    set(CMAKE_C_COMPILER /usr/local/bin/afl-gcc)
    add_definitions(-fno-omit-frame-pointer -g)
ELSE(FUZZING)
    add_definitions("-Werror")
ENDIF(FUZZING)

IF (BUILD_TESTS)
	ADD_SUBDIRECTORY(tests)
ENDIF(BUILD_TESTS)

IF (BUILD_DOC)
    ADD_SUBDIRECTORY(doc)
ENDIF(BUILD_DOC)

IF (TIME_DEBUG)
	add_definitions("-DTIME_DEBUG")
ENDIF(TIME_DEBUG)

IF (COVERAGE)
    add_definitions("-fprofile-arcs -ftest-coverage -O0")
    TARGET_LINK_LIBRARIES(rle
        gcov)
ELSE(COVERAGE)
    add_definitions("-O2")
ENDIF(COVERAGE)

INSTALL(TARGETS rle
	DESTINATION lib/)

gen_pkg_config("rle" "${DESCRIPTION_SUMMARY}" "" "")
