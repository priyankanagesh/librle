#
# Macros to get version from git tag
#

# Generic function to handle it
macro(GET_OR_READ mycommand myvariable myfile)
    # get version from command
    execute_process(
        COMMAND bash -c "${mycommand}"
        OUTPUT_VARIABLE ___local_variable
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    # if no version available from command ... get version from file
    if (NOT ___local_variable)
        message("${BoldYellow}-- ${PROJECT_NAME}: No information from command [${mycommand}] -> get it from file ${myfile}${ColourReset}")
        execute_process(
            COMMAND cat ${myfile}
            OUTPUT_VARIABLE ___local_variable
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    endif (NOT ___local_variable)
    # fill the requested variable
    if (___local_variable)
				set(${myvariable} ${___local_variable})
    endif (___local_variable)
endmacro(GET_OR_READ)

# Will set GIT_PACKAGE_VERSION
macro(GET_GIT_VERSION)
	# Get version from script or from file VERSION
	get_or_read("${CMAKE_SOURCE_DIR}/get_git_version.sh cmake" GIT_PACKAGE_VERSION ${CMAKE_CURRENT_SOURCE_DIR}/VERSION )
    message("${BoldYellow}-- ${PROJECT_NAME}: Package version ${GIT_PACKAGE_VERSION}${ColourReset}")
endmacro(GET_GIT_VERSION)

#
# Generate a pkgconfig definition file
#

macro(GEN_PKG_CONFIG target desc additional_libs inc_suffix)
    gen_pkg_config_adv("${target}" "${desc}" "${additional_libs}" "${inc_suffix}" "" "" "")
endmacro(GEN_PKG_CONFIG)

macro(GEN_PKG_CONFIG_ADV target desc additional_libs inc_suffix additional_requires additional_cflags conflicts)
    # Retrieve name and version from target
    if(NOT TARGET ${target})
        message(FATAL_ERROR "${BoldRed}Gen_pkg_config: target ${target} does not exist, aborting...${ColourReset}")
    endif(NOT TARGET ${target})
    get_target_property(NAME_PKG ${target} OUTPUT_NAME)
    if ("${NAME_PKG}" STREQUAL "NAME_PKG-NOTFOUND")
        set(NAME_PKG ${target})
    endif ("${NAME_PKG}" STREQUAL "NAME_PKG-NOTFOUND")

    get_git_version()
    set(VERSION_PKG "${GIT_PACKAGE_VERSION}")

    gen_pkg_config_adv_notarget("${NAME_PKG}" "${VERSION_PKG}" "${desc}" "${additional_libs};${NAME_PKG}" "${inc_suffix}" "${additional_requires}" "${additional_cflags}" "${conflicts}")

endmacro(GEN_PKG_CONFIG_ADV)
    
macro(GEN_PKG_CONFIG_ADV_NOTARGET name version desc additional_libs inc_suffix additional_requires additional_cflags conflicts)
    # Concatenate additionnal libs
    foreach(l ${additional_libs})
        set(ADD_LIBS_PKG "${ADD_LIBS_PKG} -l${l}")
    endforeach(l ${additional_libs})
    
    # Concatenate requires
    foreach(p ${additional_requires})
        set(ADD_REQS "${ADD_REQS} ${p}")
    endforeach(p ${additional_requires})

    # Generation
    set(PKG_CONFIG_TPL
"#System variable
prefix=@CMAKE_INSTALL_PREFIX@
libdir=\${prefix}/lib
includedir=\${prefix}/include/${inc_suffix}

#Custom variable

#Description of the Package
Name: ${name}
Description: ${desc}
Version: ${version}
Requires:${REQUIRES_PKG_${CMAKE_PROJECT_NAME}}${ADD_REQS}
Conflicts: ${conflicts}
Cflags: -I\${includedir} ${additional_cflags}
Libs:  -L\${libdir}${ADD_LIBS_PKG}")

    # Write in file
    #message(${PKG_CONFIG_TPL})
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/${name}.pc ${PKG_CONFIG_TPL})
    if(MULTIARCH_BUILD)
		install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${name}.pc DESTINATION ${PKG_CONFIG_PATH})
	else(MULTIARCH_BUILD)
		install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${name}.pc DESTINATION lib/pkgconfig)
	endif(MULTIARCH_BUILD)

endmacro(GEN_PKG_CONFIG_ADV_NOTARGET)

