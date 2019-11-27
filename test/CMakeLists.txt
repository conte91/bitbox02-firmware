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

set(TEST_COMMON_INCLUDES
    ${INCLUDES}
    ${FIRMWARE-INCLUDES}
    ${CMAKE_BINARY_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/device-test/include
)

if(CMAKE_CROSSCOMPILING)
  add_subdirectory(demo)
  add_subdirectory(device-test)
  add_subdirectory(common)
else()
  include(CTest)
  add_subdirectory(unit-test)
  if(COVERAGE)
    find_program(GCOVR gcovr)
    if(NOT GCOVR STREQUAL "GCOVR-NOTFOUND")
      # __dummy is used to always force regeneration of coverage file (There is no reasonable way to track generation of gcda files...)
      add_custom_command(
        OUTPUT gcovr/coverage.html __dummy
        COMMAND ${CMAKE_COMMAND} -E make_directory gcovr
        COMMAND ${GCOVR} --gcov-executable gcov-8 --html-details -o gcovr/coverage.html -r ${CMAKE_SOURCE_DIR} -f ${CMAKE_SOURCE_DIR}/src
      )
      add_custom_target(
        coverage
        COMMAND ${CMAKE_COMMAND} -E echo Coverage at file:///${CMAKE_BINARY_DIR}/gcovr/coverage.html
        DEPENDS gcovr/coverage.html
      )
    endif()
    find_program(LCOV lcov)
    find_program(GENHTML genhtml)
    if(NOT LCOV STREQUAL "LOCV-NOTFOUND" AND NOT GENHTML STREQUAL "GENHTML-NOTFOUND")
      add_custom_command(
        OUTPUT lcovr/raw_coverage.info lcovr/coverage.info lcovr/index.html __dummy
        COMMAND ${CMAKE_COMMAND} -E make_directory lcovr
        COMMAND ${LCOV} --capture --directory ${CMAKE_BINARY_DIR} --output-file lcovr/raw_coverage.info
        COMMAND ${LCOV} --remove lcovr/raw_coverage.info --output-file lcovr/coverage.info '*/test/*' '*/external/*' '*/src/drivers/*' '/usr/include/*' '*/tools/*'
        COMMAND ${GENHTML} lcovr/coverage.info --output-directory lcovr
      )
      add_custom_target(
        coverage-lcovr
        COMMAND ${CMAKE_COMMAND} -E echo Coverage at file:///${CMAKE_BINARY_DIR}/lcovr/index.html
        DEPENDS lcovr/index.html
      )
    endif()
  endif()
endif()
