PROJECT(librle C)

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
INCLUDE(${INFRA_PREFIX}deps/infra/cmake/a9780.cmake)

# Options
#
OPTION(BUILD_TESTS "Build simple tests" ON)
OPTION(TIME_DEBUG "Print encapsulation and deencapsulation durations" OFF)

INCLUDE_DIRECTORIES(include)

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
)

add_definitions("-g -O2 -W -Werror -Wall -Wextra -Wuninitialized
-Wstrict-prototypes -Wcast-align -Wmissing-prototypes -Wchar-subscripts
-Wpointer-arith -Winline  -Wno-conversion -Wshadow -fno-strict-aliasing")

ADD_LIBRARY(rle SHARED ${SRC_LIBRLE})

TARGET_LINK_LIBRARIES(rle
	pthread
)

IF (BUILD_TESTS)
	ADD_SUBDIRECTORY(tests)
ENDIF(BUILD_TESTS)

IF (TIME_DEBUG)
	add_definitions("-DTIME_DEBUG")
ENDIF(TIME_DEBUG)

INSTALL(TARGETS rle
	DESTINATION lib/)

#INSTALL(FILES
#	include/libs2txdriver.h
#	DESTINATION include)

gen_pkg_config("rle" "${DESCRIPTION_SUMMARY}" "" "")
