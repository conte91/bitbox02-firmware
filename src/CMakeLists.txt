# Copyright (c) 2015-2016 Lucas Betschart, Douglas J. Bakkum
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

include(cmake_common_libs.cmake)
set(INCLUDES ${INCLUDES} PARENT_SCOPE)

#-----------------------------------------------------------------------------
# Build embedded firmware


# TODO: Not needed when building bootlaoder..
# Since the nanopb is included in the source tree and not in the sysroot (/usr/local/arm-none-eabi) we have to disable searching in the sysroot.
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE NEVER)
find_package(Nanopb REQUIRED)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)


set(FIRMWARE-SOURCES
  ${DBB-FIRMWARE-SOURCES}
  ${DBB-FIRMWARE-UI-SOURCES}
  ${FIRMWARE-DRIVER-SOURCES}
  ${DRIVER-SOURCES}
  ${DBB-FIRMWARE-PROTOBUF-SOURCES}
  ${CRYPTOAUTHLIB-SOURCES}
  ${ETHEREUM-SOURCES}
  ${CMAKE_SOURCE_DIR}/src/common_main.c
)

set(BOOTLOADER-SOURCES
  ${DBB-BOOTLOADER-SOURCES}
  ${DRIVER-SOURCES}
)

set_source_files_properties(
  ${DBB-FIRMWARE-PROTOBUF-SOURCES}
  PROPERTIES GENERATED TRUE
)

if(CMAKE_CROSSCOMPILING)
  get_property(SAMD51A_INCLUDES TARGET samd51a-ds PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
  get_property(ASF4_MIN_INCLUDES TARGET asf4-drivers-min PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
  get_property(ASF4_INCLUDES TARGET asf4-drivers PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
  get_property(CMSIS_INCLUDES TARGET CMSIS PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
  get_property(WALLY_INCLUDES TARGET wallycore PROPERTY INTERFACE_INCLUDE_DIRECTORIES)

  set(RUST_INCLUDES ${INCLUDES} ${SYSTEMINCLUDES} ${SAMD51A_INCLUDES} ${ASF4_INCLUDES} ${ASF4_MIN_INCLUDES} ${CMSIS_INCLUDES} ${NANOPB_INCLUDE_DIRS} ${WALLY_INCLUDES})

  if(CMAKE_BUILD_TYPE STREQUAL "DEBUG")
    set(RUST_PROFILE "debug")
  else()
    set(RUST_PROFILE "release")
    set(RUST_CARGO_FLAG "--release")
  endif()

  set(LIBBITBOX02_RUST_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/rust/bitbox02-rust)
  set(LIBBITBOX02_RUST_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/rust/bitbox02-rust/target)
  set(LIBBITBOX02_RUST ${CMAKE_CURRENT_BINARY_DIR}/rust/bitbox02-rust/target/thumbv7em-none-eabi/${RUST_PROFILE}/libbitbox02_rust.a)

  find_program(CBINDGEN cbindgen)
  find_program(CARGO cargo)

  add_custom_target(rust
    # Build rust library
    COMMAND
      ${CMAKE_COMMAND} -E env SYSROOT=${CMAKE_SYSROOT} INCLUDES="${RUST_INCLUDES}" ${CARGO} build --manifest-path ${LIBBITBOX02_RUST_SOURCE_DIR}/Cargo.toml --target-dir ${LIBBITBOX02_RUST_BINARY_DIR} ${RUST_CARGO_FLAG} --target thumbv7em-none-eabi
    # Rust packages stdlib functions which we must remove/weaken
    COMMAND
      ${CMAKE_OBJCOPY} -N memset -N memcpy -N memmove -W memcmp ${LIBBITBOX02_RUST}
    BYPRODUCTS
      ${LIBBITBOX02_RUST}
  )

  add_custom_target(rust-test
    COMMAND
      ${CMAKE_COMMAND} -E env INCLUDES="${RUST_INCLUDES}" ${CARGO} test --manifest-path ${CMAKE_CURRENT_SOURCE_DIR}/rust/bitbox02-sys/Cargo.toml --target-dir ${LIBBITBOX02_RUST_BINARY_DIR} ${RUST_CARGO_FLAG}
    COMMAND
      ${CMAKE_COMMAND} -E env INCLUDES="${RUST_INCLUDES}" ${CARGO} test --manifest-path ${CMAKE_CURRENT_SOURCE_DIR}/rust/bitbox02/Cargo.toml --target-dir ${LIBBITBOX02_RUST_BINARY_DIR} ${RUST_CARGO_FLAG}
    COMMAND
      ${CMAKE_COMMAND} -E env INCLUDES="${RUST_INCLUDES}" ${CARGO} test --manifest-path ${LIBBITBOX02_RUST_SOURCE_DIR}/Cargo.toml --target-dir ${LIBBITBOX02_RUST_BINARY_DIR} ${RUST_CARGO_FLAG}
    )

  add_custom_target(rust-bindgen
    # Generate c-headers for the rust library
    COMMAND
      ${CBINDGEN} --config ${CMAKE_CURRENT_SOURCE_DIR}/rust/cbindgen.toml --output ${CMAKE_CURRENT_BINARY_DIR}/rust/bitbox02_rust.h ${LIBBITBOX02_RUST_SOURCE_DIR}
    BYPRODUCTS
      ${CMAKE_CURRENT_BINARY_DIR}/rust/bitbox02_rust.h
  )

  # TODO(nc): Add dependency on global "doc" target on this when api-docs branch is merged
  add_custom_target(rust-docs
    COMMAND
      ${CMAKE_COMMAND} -E env SYSROOT=${CMAKE_SYSROOT} INCLUDES="${RUST_INCLUDES}" ${CARGO} doc --document-private-items --manifest-path ${LIBBITBOX02_RUST_SOURCE_DIR}/Cargo.toml --target-dir ${CMAKE_BINARY_DIR}/docs-rust ${RUST_CARGO_FLAG} --target thumbv7em-none-eabi
    COMMAND
      ${CMAKE_COMMAND} -E echo "See docs at file://${CMAKE_BINARY_DIR}/docs-rust/thumbv7em-none-eabi/doc/bitbox02_rust/index.html"
  )

  add_library(bitbox02_rust STATIC IMPORTED)
  set_property(TARGET bitbox02_rust PROPERTY IMPORTED_LOCATION ${LIBBITBOX02_RUST})

  set(STACK_SIZE "0x10000" CACHE STRING "Specify stack size for bootloader/firmware")
  set(STACK_SIZE ${STACK_SIZE} PARENT_SCOPE)
  set(HEAP_SIZE "0x18000" CACHE STRING "Specify heap size for bootloader/firmware")
  set(HEAP_SIZE ${HEAP_SIZE} PARENT_SCOPE)

  # If a bootloader that locks the bootloader is flashed the bootloader area is permanently read-only.
  set(BOOTLOADERS-BITBOX02
    bootloader # Runs signed firmware
    bootloader-development # Runs signed/unsigned firmware and has bootloader menu
    bootloader-development-locked # Runs signed/unsigned firmware, has bootloader menu and bootloader is locked
    bootloader-semihosting # Runs signed/unsigned firmware, has bootloader menu and enables semihosting
    bootloader-production # Runs signed firmware and bootloader is locked
    bootloader-btc # Runs signed (btc-only keys) firmware
    bootloader-btc-development # Runs signed/unsigned firmware and has bootloader menu
    bootloader-btc-production # Runs signed (btc-only keys) firmware and bootloader is locked
  )
  set(BOOTLOADERS-BITBOXBASE
    bootloader-bitboxbase # Runs signed (base keys) firmware
    bootloader-bitboxbase-development # Runs signed/unsigned firmware and has bootloader menu
    bootloader-bitboxbase-semihosting # Runs signed/unsigned firmware, has bootloader menu and enables semihosting
    bootloader-bitboxbase-production # Runs signed (base keys) firmware and bootloader is locked
  )
  set(BOOTLOADERS
    ${BOOTLOADERS-BITBOX02}
    ${BOOTLOADERS-BITBOXBASE}
  )
  set(BOOTLOADERS ${BOOTLOADERS} PARENT_SCOPE)
  foreach(bootloader ${BOOTLOADERS})
    set(elf ${bootloader}.elf)
    add_executable(${elf} ${BOOTLOADER-SOURCES})
    target_link_libraries(${elf} PRIVATE c asf4-drivers-min -Wl,-u,exception_table)
    target_include_directories(${elf} PRIVATE ${INCLUDES})
    target_include_directories(${elf} SYSTEM PRIVATE ${SYSTEMINCLUDES})
    target_compile_definitions(${elf} PRIVATE BOOTLOADER)
    # needed to find version.h
    target_include_directories(${elf} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    # needed to find bootloader_version.h
    target_include_directories(${elf} PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/bootloader)
    target_link_libraries(${elf} PRIVATE "-Wl,-Map=\"${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${bootloader}.map\" -T\"${CMAKE_SOURCE_DIR}/bootloader.ld\"")
    target_link_libraries(${elf} PRIVATE -Wl,--defsym=STACK_SIZE=${STACK_SIZE} -Wl,-defsym=HEAP_SIZE=${HEAP_SIZE})
    target_link_libraries(${elf} PRIVATE ${QTOUCHLIB_A} ${QTOUCHLIB_B} ${QTOUCHLIB_T})
    # Select the smaller version of libc called nano.
    target_compile_options(${elf} PRIVATE --specs=nano.specs)
    target_link_libraries(${elf} PRIVATE --specs=nano.specs)
    string(FIND ${bootloader} semihosting SEMIHOSTING_FOUND)
    if(SEMIHOSTING_FOUND EQUAL -1)
      target_compile_options(${elf} PRIVATE --specs=nosys.specs)
      target_link_libraries(${elf} PRIVATE --specs=nosys.specs)
    else()
      # Select an implementation of the system calls that can communicate with the debugger
      target_compile_options(${elf} PRIVATE --specs=rdimon.specs)
      target_link_libraries(${elf} PRIVATE --specs=rdimon.specs)
    endif()
  endforeach(bootloader)

  foreach(bootloader ${BOOTLOADERS-BITBOX02})
      target_sources(${bootloader}.elf PRIVATE ${PLATFORM-BITBOX02-SOURCES})
  endforeach(bootloader)
  foreach(bootloader ${BOOTLOADERS-BITBOXBASE})
      target_sources(${bootloader}.elf PRIVATE ${PLATFORM-BITBOXBASE-SOURCES})
  endforeach(bootloader)

  target_compile_definitions(bootloader.elf PRIVATE PRODUCT_BITBOX_MULTI)
  target_compile_definitions(bootloader-development.elf PRIVATE PRODUCT_BITBOX_MULTI BOOTLOADER_DEVDEVICE)
  target_compile_definitions(bootloader-semihosting.elf PRIVATE PRODUCT_BITBOX_MULTI BOOTLOADER_DEVDEVICE SEMIHOSTING)
  target_compile_definitions(bootloader-development-locked.elf PRIVATE PRODUCT_BITBOX_MULTI BOOTLOADER_DEVDEVICE BOOTLOADER_PRODUCTION)
  set_property(TARGET bootloader-development-locked.elf PROPERTY EXCLUDE_FROM_ALL ON)


  target_compile_definitions(bootloader-production.elf PRIVATE PRODUCT_BITBOX_MULTI BOOTLOADER_PRODUCTION)
  set_property(TARGET bootloader-production.elf PROPERTY EXCLUDE_FROM_ALL ON)

  target_compile_definitions(bootloader-btc.elf PRIVATE PRODUCT_BITBOX_BTCONLY)
  target_compile_definitions(bootloader-btc-development.elf PRIVATE PRODUCT_BITBOX_BTCONLY BOOTLOADER_DEVDEVICE)
  target_compile_definitions(bootloader-btc-production.elf PRIVATE PRODUCT_BITBOX_BTCONLY BOOTLOADER_PRODUCTION)
  set_property(TARGET bootloader-btc-production.elf PROPERTY EXCLUDE_FROM_ALL ON)

  target_compile_definitions(bootloader-bitboxbase.elf PRIVATE PRODUCT_BITBOX_BASE)
  target_compile_definitions(bootloader-bitboxbase-development.elf PRIVATE BOOTLOADER_DEVDEVICE PRODUCT_BITBOX_BASE)
  target_compile_definitions(bootloader-bitboxbase-semihosting.elf PRIVATE BOOTLOADER_DEVDEVICE PRODUCT_BITBOX_BASE SEMIHOSTING)
  target_compile_definitions(bootloader-bitboxbase-production.elf PRIVATE BOOTLOADER_PRODUCTION PRODUCT_BITBOX_BASE)
  set_property(TARGET bootloader-bitboxbase-production.elf PROPERTY EXCLUDE_FROM_ALL ON)

  set(FIRMWARES
    firmware # Firmware MULTI
    firmware-semihosting # Firmware MULTI with semihosting enabled
    firmware-btc # Firmware BTC-ONLY
    firmware-bitboxbase # Firmware BASE
    firmware-bitboxbase-semihosting # Firmware BASE with semihosting
    factory-setup # Factory-setup
    factory-setup-bitboxbase # Factory-setup
  )
  set(FIRMWARES ${FIRMWARES} PARENT_SCOPE)
  foreach(firmware ${FIRMWARES})
    set(elf ${firmware}.elf)
    add_executable(${elf} ${FIRMWARE-SOURCES})
    target_link_libraries(${elf}
      PRIVATE
        cryptoauthlib
        fatfs
        base32
        bignum # TODO: only eth
        sha3   # TODO: Only eth
        ctaes
        c
        samd51a-ds
        asf4-drivers-min
        asf4-drivers
        -Wl,-u,exception_table)
    add_dependencies(${elf} generate-protobufs)
    target_include_directories(${elf} PRIVATE ${INCLUDES})
    target_include_directories(${elf} SYSTEM PRIVATE ${SYSTEMINCLUDES})

    # Include and provide configuration for nanopb
    target_include_directories(${elf} SYSTEM PRIVATE ${NANOPB_INCLUDE_DIRS})
    target_compile_definitions(${elf} PRIVATE "PB_NO_PACKED_STRUCTS=1" "PB_FIELD_16BIT=1")

    # needed to find version.h
    target_include_directories(${elf} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(${elf} PRIVATE "-Wl,-Map=\"${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${firmware}.map\" -T\"${CMAKE_SOURCE_DIR}/firmware.ld\"")
    target_link_libraries(${elf} PRIVATE -Wl,--defsym=STACK_SIZE=${STACK_SIZE} -Wl,-defsym=HEAP_SIZE=${HEAP_SIZE})

    add_dependencies(${elf} noise-c)
    target_link_libraries(${elf} PRIVATE noiseprotocol)

    add_dependencies(${elf} libwally-core)
    target_link_libraries(${elf} PRIVATE wallycore secp256k1)
    target_link_libraries(${elf} PRIVATE ${QTOUCHLIB_A} ${QTOUCHLIB_B} ${QTOUCHLIB_T})
    # Must manually link against C so that malloc can find _sbrk

    # Select the smaller version of libc called nano.
    target_compile_options(${elf} PRIVATE --specs=nano.specs)
    target_link_libraries(${elf} PRIVATE --specs=nano.specs)
    string(FIND ${firmware} semihosting SEMIHOSTING_FOUND)
    if(SEMIHOSTING_FOUND EQUAL -1)
      target_compile_options(${elf} PRIVATE --specs=nosys.specs)
      target_link_libraries(${elf} PRIVATE --specs=nosys.specs)
    else()
      # Select an implementation of the system calls that can communicate with the debugger
      target_compile_options(${elf} PRIVATE --specs=rdimon.specs)
      target_link_libraries(${elf} PRIVATE --specs=rdimon.specs)
    endif()
  endforeach(firmware)

  target_sources(firmware.elf PRIVATE firmware.c)
  target_compile_definitions(firmware.elf PRIVATE PRODUCT_BITBOX_MULTI APP_BTC APP_LTC APP_ETH APP_U2F)
  target_sources(firmware.elf PRIVATE ${FIRMWARE-U2F-SOURCES})
  target_link_libraries(firmware.elf PRIVATE bitbox02-standard)

  target_sources(firmware-semihosting.elf PRIVATE firmware.c)
  target_sources(firmware-semihosting.elf PRIVATE ${FIRMWARE-U2F-SOURCES})
  target_link_libraries(firmware-semihosting.elf PRIVATE bitbox02-standard-semihosting)
  # Select an implementation of the system calls that can communicate with the debugger
  target_compile_definitions(firmware-semihosting.elf PRIVATE PRODUCT_BITBOX_MULTI APP_BTC APP_LTC APP_ETH APP_U2F)
  target_compile_definitions(firmware-semihosting.elf PRIVATE SEMIHOSTING)

  target_sources(firmware-btc.elf PRIVATE firmware.c)
  target_compile_definitions(firmware-btc.elf PRIVATE PRODUCT_BITBOX_BTCONLY APP_BTC)
  target_link_libraries(firmware-btc.elf PRIVATE bitbox02-btc)

  target_sources(firmware-bitboxbase.elf PRIVATE bitboxbase/bitboxbase.c commander/commander_bitboxbase.c)
  target_compile_definitions(firmware-bitboxbase.elf PRIVATE PRODUCT_BITBOX_BASE)
  target_sources(firmware-bitboxbase.elf PRIVATE ${BITBOXBASE-FIRMWARE-SOURCES})
  target_link_libraries(firmware-bitboxbase.elf PRIVATE bitboxbase-standard)

  target_sources(firmware-bitboxbase-semihosting.elf PRIVATE bitboxbase/bitboxbase.c)
  target_compile_definitions(firmware-bitboxbase-semihosting.elf PRIVATE PRODUCT_BITBOX_BASE SEMIHOSTING)
  target_sources(firmware-bitboxbase-semihosting.elf PRIVATE ${BITBOXBASE-FIRMWARE-SOURCES})
  target_link_libraries(firmware-bitboxbase-semihosting.elf PRIVATE bitboxbase-standard-semihosting)

  target_link_libraries(firmware-bitboxbase.elf PRIVATE bitbox02_rust)
  add_dependencies(firmware-bitboxbase.elf rust rust-bindgen)

  target_sources(factory-setup.elf PRIVATE factorysetup.c)
  target_compile_definitions(factory-setup.elf PRIVATE PRODUCT_BITBOX02_FACTORYSETUP)
  target_link_libraries(factory-setup.elf PRIVATE bitbox02-btc)

  target_sources(factory-setup-bitboxbase.elf PRIVATE factorysetup.c)
  target_compile_definitions(factory-setup-bitboxbase.elf PRIVATE PRODUCT_BITBOXBASE_FACTORYSETUP)
  target_link_libraries(factory-setup-bitboxbase.elf PRIVATE bitboxbase-standard)

  foreach(name ${BOOTLOADERS} ${FIRMWARES})
    add_custom_command(
      TARGET ${name}.elf POST_BUILD
      COMMAND ${CMAKE_SIZE} ${name}.elf
      COMMAND ${CMAKE_OBJCOPY} -O binary ${name}.elf ${name}.bin
      WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
      COMMENT "\nGenerating binary ${name}.bin"
    )
    # Fail on warnings for our builds
    target_compile_options(${name}.elf PRIVATE "-Werror")
  endforeach()
endif()
