
cmake_minimum_required(VERSION 3.22.1)

project("encrypt")



set(GMSSL_DIR /home/liuxin/gitProjects/GmSSL-3.1.1)


include_directories(${GMSSL_DIR}\\include)
link_directories(${GMSSL_DIR}\\arm64_static)



set(ENCRYPT_SRC

        main.c
        util/hex_util.c
        util/log_util.h
)




add_library(${CMAKE_PROJECT_NAME} SHARED
        ${ENCRYPT_SRC})


target_link_libraries(${CMAKE_PROJECT_NAME}
        android
        log
        gmssl
)
