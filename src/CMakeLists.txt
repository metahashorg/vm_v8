include_directories(.)
include_directories(~/local/vm_v8/src/v8)
include_directories(~/local/vm_v8/src/v8/include)
link_directories(~/local/vm_v8/src/v8/lib)
link_directories(/usr/local/lib/sniper)

add_definitions(-DSNIPER_LOG_TRACE -DSNIPER_LOG_DEBUG)

set(PROJECT_HEADERS
	RIPEMD160.h
	jscode.h
	external/functions/print.hpp
        external/functions/sha256.hpp
        external/functions/check_sign.hpp
	external/variables/test.hpp
	external/functions/address_from_pubkey.hpp
	utils.h
    )


set(PROJECT_SOURCES
    )


set(PROJECT_MAIN
    RIPEMD160.cpp
    utils.cpp
    stdcapture.hpp
    main.cpp
    )

#Threads
find_package(Threads)
find_package(fmt REQUIRED)
#Sniper
find_package(Sniper REQUIRED)
#OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

set(PROJECT_LIBS 
    ${CMAKE_THREAD_LIBS_INIT}
    ${OPENSSL_LIBRARIES}
    rt.a
    m.a
    z.a
    -licui18n
    -licuuc
    -lv8
    -lv8_libbase
    -lv8_libplatform
    -lc++
	-ldl
	-lz
    )


#APP
add_executable(${PROJECT_NAME} ${PROJECT_MAIN})
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wno-unused-parameter -g -rdynamic")
target_link_libraries(${PROJECT_NAME} ${PROJECT_LIBS})
