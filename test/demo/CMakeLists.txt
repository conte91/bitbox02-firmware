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

set(INCLUDES ${TEST_COMMON_INCLUDES})

include_directories(${NANOPB_INCLUDE_DIRS})

set(BB02_DEMO_LIST)

add_custom_target(demo)

foreach(name ${BB02_DEMO_LIST})
  set(elf ${name}.elf)
  add_executable(${elf} ${CMAKE_CURRENT_SOURCE_DIR}/src/test_${name}.c)

  target_include_directories(${elf} PRIVATE ${INCLUDES})
  target_link_libraries(${elf} PRIVATE "-Wl,-Map=\"${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test_${name}.map\" -T\"${CMAKE_SOURCE_DIR}/src/firmware.ld\"")
  target_link_libraries(${elf} PRIVATE -Wl,--defsym=STACK_SIZE=${STACK_SIZE} -Wl,-defsym=HEAP_SIZE=${HEAP_SIZE})

  # Since noiseprotocol and wallycore are external projects we need to specify the dependency
  add_dependencies(${elf} noise-c)
  add_dependencies(${elf} libwally-core)
  # We must link against libc before libbitbox because malloc depends on _sbrk
  # We must mark "exception_table" as used, otherwise it won't be linked in since it is in a static library
  target_link_libraries(${elf}
    PRIVATE
      c
      bitbox02-standard
      asf4-drivers-min
      ${QTOUCHLIB_A}
      ${QTOUCHLIB_B}
      ${QTOUCHLIB_T}
  )

  add_custom_command(
    TARGET ${elf} POST_BUILD
    COMMAND ${CMAKE_SIZE} ${elf}
    COMMAND ${CMAKE_OBJCOPY} -O binary ${elf} ${name}.bin
    WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
    COMMENT "\nGenerating binary ${name}.bin"
  )
  if(PYTHONINTERP_FOUND)
    execute_process(
      COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_SOURCE_DIR}/scripts/expand_template ${CMAKE_SOURCE_DIR}/scripts/template-firmware.jlink file=build/bin/${name}.bin -o ${name}.jlink
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
  add_dependencies(demo ${elf})
  endif()
endforeach()

set(BBB_DEMO_LIST
  hsm_led_show
)

foreach(name ${BBB_DEMO_LIST})
  set(elf ${name}.elf)
  add_executable(${elf} ${CMAKE_CURRENT_SOURCE_DIR}/src/${name}.c)

  target_include_directories(${elf} PRIVATE ${INCLUDES})
  target_link_libraries(${elf} PRIVATE "-Wl,-Map=\"${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test_${name}.map\" -T\"${CMAKE_SOURCE_DIR}/firmware.ld\"")
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
      bitboxbase-standard
      c
      ${QTOUCHLIB_A}
      ${QTOUCHLIB_B}
      ${QTOUCHLIB_T}
  )

  add_custom_command(
    TARGET ${elf} POST_BUILD
    COMMAND ${CMAKE_SIZE} ${elf}
    COMMAND ${CMAKE_OBJCOPY} -O binary ${elf} ${name}.bin
    WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
    COMMENT "\nGenerating binary ${name}.bin"
  )
  if(PYTHONINTERP_FOUND)
    execute_process(
      COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_SOURCE_DIR}/scripts/expand_template ${CMAKE_SOURCE_DIR}/scripts/template-firmware.jlink file=build/bin/${name}.bin -o ${name}.jlink
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
  add_dependencies(demo ${elf})
  endif()
endforeach()
