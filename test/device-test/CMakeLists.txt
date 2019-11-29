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


#-----------------------------------------------------------------------------
# Source files

# CMake is a bit retarted and doesn't keep some properties between directories...
set_source_files_properties(
  ${DBB-FIRMWARE-PROTOBUF-SOURCES}
  PROPERTIES GENERATED TRUE
)

include_directories(${NANOPB_INCLUDE_DIRS})

set(BB02_TEST_LIST
  all_variants_menu
  backup
  bip39
  button_tap
  confirm_bip39
  entry_screen
  scroll_menu
  scroll_menu_2
  simple_slide
  slide_info
  ssp
  tap_menu
  trace
  usb_cmd_process
  usb_composed_ep_in
  usb_composed_ep_out
  usb_d_init
  usb_hww_ep_in
  usb_hww_ep_out
  usb_u2f_ep_in
  usb_u2f_ep_out
  usbdc_init
  write_sd
)

add_custom_target(device-tests)
add_library(device-tests-common ${CMAKE_CURRENT_SOURCE_DIR}/src/framework/test_common.c)
target_include_directories(device-tests-common PUBLIC ${TEST_INCLUDES})
target_link_libraries(device-tests-common
    bitbox02-standard-semihosting
    asf4-drivers-min
    ${QTOUCHLIB_A}
    ${QTOUCHLIB_B}
    ${QTOUCHLIB_T}
    )

foreach(name ${BB02_TEST_LIST})
  set(elf fw_test_${name}.elf)
  add_executable(${elf} ${CMAKE_CURRENT_SOURCE_DIR}/src/test_${name}.c)

  message("INCLUDES: ${TEST_INCLUDES}")
  #target_include_directories(${elf} PRIVATE ${INCLUDES})
  target_link_libraries(${elf} PRIVATE "-Wl,-Map=\"${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test_${name}.map\" -T\"${CMAKE_CURRENT_SOURCE_DIR}/device-test.ld\"")
  target_link_libraries(${elf} PRIVATE -Wl,--defsym=STACK_SIZE=${STACK_SIZE} -Wl,-defsym=HEAP_SIZE=${HEAP_SIZE})
  target_link_libraries(${elf} PRIVATE --specs=nano.specs --specs=rdimon.specs)
  target_compile_options(${elf} PRIVATE --specs=nano.specs --specs=rdimon.specs)

  # Since noiseprotocol and wallycore are external projects we need to specify the dependency
  add_dependencies(${elf} noise-c)
  add_dependencies(${elf} libwally-core)
  # We must link against libc before libbitbox because malloc depends on _sbrk
  # We must mark "exception_table" as used, otherwise it won't be linked in since it is in a static library
  target_link_libraries(${elf}
    PRIVATE
      c
      device-tests-common
  )

  add_custom_command(
    TARGET ${elf} POST_BUILD
    COMMAND ${CMAKE_SIZE} ${elf}
    COMMAND ${CMAKE_OBJCOPY} -O binary ${elf} fw_test_${name}.bin
    WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
    COMMENT "\nGenerating binary fw_test_${name}.bin"
  )
  if(PYTHONINTERP_FOUND)
    execute_process(
      COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_SOURCE_DIR}/scripts/expand_template ${CMAKE_SOURCE_DIR}/scripts/template-firmware.jlink file=build/bin/fw_test_${name}.bin -o fw_test_${name}.jlink
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
  add_dependencies(device-tests ${elf})
  endif()
endforeach()

set(BBB_TEST_LIST)

foreach(name ${BBB_TEST_LIST})
  set(elf fw_test_${name}.elf)
  add_executable(${elf} ${CMAKE_CURRENT_SOURCE_DIR}/src/test_${name}.c)

  target_include_directories(${elf} PRIVATE ${TEST_INCLUDES})
  target_link_libraries(${elf} PRIVATE "-Wl,-Map=\"${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test_${name}.map\" -T\"${CMAKE_CURRENT_SOURCE_DIR}/device-test.ld\"")
  target_link_libraries(${elf} PRIVATE -Wl,--defsym=STACK_SIZE=${STACK_SIZE} -Wl,-defsym=HEAP_SIZE=${HEAP_SIZE})

  # Since noiseprotocol and wallycore are external projects we need to specify the dependency
  add_dependencies(${elf} noise-c)
  add_dependencies(${elf} libwally-core)
  # We must link against libc before libbitbox because malloc depends on _sbrk
  # We must mark "exception_table" as used, otherwise it won't be linked in since it is in a static library
  target_link_libraries(${elf}
    PRIVATE
      asf4-drivers-min
      asf4-drivers
      bitboxbase-standard-semihosting
      c
      ${QTOUCHLIB_A}
      ${QTOUCHLIB_B}
      ${QTOUCHLIB_T}
  )

  add_custom_command(
    TARGET ${elf} POST_BUILD
    COMMAND ${CMAKE_SIZE} ${elf}
    COMMAND ${CMAKE_OBJCOPY} -O binary ${elf} fw_test_${name}.bin
    WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
    COMMENT "\nGenerating binary fw_test_${name}.bin"
  )
  if(PYTHONINTERP_FOUND)
    execute_process(
      COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_SOURCE_DIR}/scripts/expand_template ${CMAKE_SOURCE_DIR}/scripts/template-firmware.jlink file=build/bin/fw_test_${name}.bin -o fw_test_${name}.jlink
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
  add_dependencies(device-tests ${elf})
  endif()
endforeach()
