# Copyright 2019 Shift Cryptosecurity AG
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# CMake is a bit retarted and doesn't keep some properties between directories...
set_source_files_properties(
  ${DBB-FIRMWARE-PROTOBUF-SOURCES}
  PROPERTIES GENERATED TRUE
)

set(apps-bitbox02-standard "APP_BTC" "APP_LTC" "APP_U2F" "APP_ETH")
set(apps-bitboxbase)
set(bitbox02-sources
    ${PLATFORM-BITBOX02-SOURCES}
    ${DBB-FIRMWARE-SOURCES}
    ${DBB-FIRMWARE-UI-SOURCES}
    ${FIRMWARE-DRIVER-SOURCES}
    ${DRIVER-SOURCES}
    ${DBB-FIRMWARE-PROTOBUF-SOURCES}
    ${CRYPTOAUTHLIB-SOURCES}
    ${ETHEREUM-SOURCES}
    ${FIRMWARE-U2F-SOURCES}
    ${CMAKE_SOURCE_DIR}/src/common_main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../device-test/src/framework/test_common.c
    )
set(bitboxbase-sources
    ${PLATFORM-BITBOXBASE-SOURCES}
    ${DBB-FIRMWARE-SOURCES}
    ${DBB-FIRMWARE-UI-SOURCES}
    ${FIRMWARE-DRIVER-SOURCES}
    ${DRIVER-SOURCES}
    ${DBB-FIRMWARE-PROTOBUF-SOURCES}
    ${CRYPTOAUTHLIB-SOURCES}
    ${CMAKE_SOURCE_DIR}/src/common_main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../device-test/src/framework/test_common.c
    )
set(bitbox02-standard "bitbox02" "standard" bitbox02-sources FALSE apps-bitbox02-standard)
set(bitbox02-standard-semihosting "bitbox02" "standard" bitbox02-sources TRUE apps-bitbox02-standard)
set(bitboxbase-standard "bitboxbase" "standard" bitboxbase-sources FALSE apps-bitboxbase)
set(bitboxbase-standard-semihosting "bitboxbase" "standard" bitboxbase-sources TRUE apps-bitboxbase)

set(configurations bitbox02-standard bitbox02-standard-semihosting bitboxbase-standard bitboxbase-standard-semihosting)

function(get_product_name platform product ret)
    if ("${platform}" STREQUAL "bitboxbase")
        if ("${product}" STREQUAL "standard")
            set("${ret}" "PRODUCT_BITBOX_BASE" PARENT_SCOPE)
            return()
        endif()
    elseif ("${platform}" STREQUAL "bitbox02")
        if ("${product}" STREQUAL "standard")
            set("${ret}" "PRODUCT_BITBOX_MULTI" PARENT_SCOPE)
            return()
        elseif ("${product}" STREQUAL "btc")
            set("${ret}" "PRODUCT_BITBOX_BTCONLY" PARENT_SCOPE)
            return()
        endif()
    endif()
    message(FATAL_ERROR "Invalid product ${product} for platform ${platform}")
endfunction()

function(generate_target platform product sources semihosting apps)
    set(target_name "${platform}-${product}")
    if (${semihosting})
        set(target_name "${target_name}-semihosting")
    endif()

    message("Adding target: ${target_name} with sources: ${sources}")
    add_library("${target_name}"
      STATIC
      ${FIRMWARE_SOURCES}
      ${${sources}}
    )

    target_include_directories(${target_name} PRIVATE ${TEST_COMMON_INCLUDES})
    target_include_directories(${target_name} SYSTEM PUBLIC ${SYSTEMINCLUDES})
    target_include_directories(${target_name} SYSTEM PUBLIC ${NANOPB_INCLUDE_DIRS})
    target_compile_definitions(${target_name} PUBLIC "PB_NO_PACKED_STRUCTS=1" "PB_FIELD_16BIT=1")
    target_compile_definitions(${target_name} PUBLIC ${${apps}})
    add_dependencies(${target_name} generate-protobufs)
    # needed to find version.h
    target_include_directories(${target_name} SYSTEM PUBLIC ${CMAKE_BINARY_DIR}/src)
    target_link_libraries(${target_name}
      PUBLIC
        wallycore
        secp256k1
      PRIVATE
        fatfs
        noiseprotocol
        cryptoauthlib
        base32
        bignum # TODO: only eth
        sha3   # TODO: Only eth
        ctaes
        -Wl,-u,exception_table
    )

    # Always enable semihosting for the test firmwares
    get_product_name("${platform}" "${product}" product_name)
    target_compile_definitions(${target_name} PUBLIC "${product_name}")
    if (${semihosting})
        target_compile_definitions(${target_name} PUBLIC "SEMIHOSTING")
    endif()

    target_link_libraries(${target_name} PUBLIC --specs=nano.specs --specs=rdimon.specs)
    target_compile_options(${target_name} PUBLIC --specs=nano.specs --specs=rdimon.specs)
endfunction()

foreach(configuration ${configurations})
    list(GET ${configuration} 0 platform)
    list(GET ${configuration} 1 product)
    list(GET ${configuration} 2 sources)
    list(GET ${configuration} 3 semihosting)
    list(GET ${configuration} 4 apps)
    generate_target(${platform} ${product} "${sources}" "${semihosting}" "${apps}")
endforeach()
