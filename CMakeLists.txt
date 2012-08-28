PROJECT(librle C)

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

SET(PACKAGE_NAME librle)

SET(CPACK_PACKAGE_VERSION ${PACKAGE_VERSION})

SET(VERSION ${PACKAGE_VERSION})

SET(PACKAGE_CONTACT "Aurelien CASTANIE acastanie@ausy.org")

SET(CPACK_PACKAGE_NAME "librle")

INCLUDE_DIRECTORIES(include)

SET(SRC
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

SET(CMAKE_C_FLAGS "-g -Wall -Werror")

ADD_LIBRARY(rle SHARED ${SRC})

#TARGET_LINK_LIBRARIES(librle
#	pthread
#)

#ADD_SUBDIRECTORY(tests)

# FROM libsach
macro(GET_OR_READ mycommand myvariable myfile)
	# get version from command
	execute_process(
		COMMAND bash -c "${mycommand}"
		OUTPUT_VARIABLE ___local_variable
		OUTPUT_STRIP_TRAILING_WHITESPACE)
	# if no version available from command ... get version from file
	if (NOT ___local_variable)
		message("no information from command [${mycommand}] -> get it from file ${myfile}")
		execute_process(
			COMMAND cat ${myfile}
			OUTPUT_VARIABLE ___local_variable
			OUTPUT_STRIP_TRAILING_WHITESPACE)
        else (NOT ___local_variable)
		# Fill version in file for future use
		execute_process(
			COMMAND bash -c "echo ${___local_variable} > ${myfile}")
	endif (NOT ___local_variable)
	# fill the requested variable
	if (___local_variable)
		set(${myvariable} ${___local_variable})
	endif (___local_variable)
endmacro(GET_OR_READ)

# get version from git or from file
GET_OR_READ("git describe --tags" GIT_PACKAGE_VERSION ${CMAKE_SOURCE_DIR}/VERSION )

# if no version availble at all --- What can we do ?
if (NOT GIT_PACKAGE_VERSION)
	message("/!\\ No version information /!\\")
	set(GIT_PACKAGE_VERSION "0.0.1")
endif (NOT GIT_PACKAGE_VERSION)

# rpm does not like version with '-' in it
string(REGEX REPLACE - ~ PACKAGE_VERSION ${GIT_PACKAGE_VERSION})

SET(PKG_CONFIG_REQUIRES "")
SET(PKG_CONFIG_CONFLICTS "")
SET(PKG_CONFIG_LIBS "-lrle")
#configure_file(templates/template.pc.in ${CMAKE_BINARY_DIR}/${PACKAGE_NAME}.pc @ONLY)

#CONFIGURE_FILE(templates/Doxyfile.in ${CMAKE_BINARY_DIR}/Doxyfile @ONLY)
#ADD_CUSTOM_TARGET(doc doxygen Doxyfile
#        WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

SET(CPACK_SET_DESTDIR ON)
SET(CPACK_SOURCE_STRIP_FILES ON)
SET(CPACK_PACKAGE_VERSION ${PACKAGE_VERSION})
SET(CPACK_PACKAGE_VENDOR ${PACKAGE_VENDOR})

SET(CPACK_GENERATOR "DEB")
SET(CPACK_PACKAGE_DESCRIPTION "RLE library")

SET(CPACK_RPM_PACKAGE_REQUIRES ${RPM_PACKAGE_REQUIRES})
SET(CPACK_RPM_USER_BINARY_SPECFILE  ${CMAKE_SOURCE_DIR}/templates/${CPACK_PACKAGE_NAME}.spec.in)
SET(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}")
SET(CPACK_SOURCE_PACKAGE_FILE_NAME "${PACKAGE_NAME}-${PACKAGE_VERSION}-src")
SET(CPACK_SOURCE_GENERATOR "TGZ")
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY ${PACKAGE_DESCRIPTION_SUMMARY})
SET(CPACK_PACKAGE_CONTACT ${PACKAGE_CONTACT})
SET(CPACK_SOURCE_IGNORE_FILES
	"/\\\\.git/;/submodules/;/build/;\\\\CMakeFiles;\\\\.tar\\\\.gz$;/_CPack_Packages/;CMakeCache;\\\\.o$;\\\\.so$;/CVS/;/\\\\.svn/;\\\\.swp$;\\\\.#;/#;.*~;cscope.*")
SET(CPACK_GENERATOR "RPM")
SET(CPACK_GENERATOR "DEB")

INCLUDE(CPack)
