# If not stated otherwise in this file or this component's license file the
# following copyright and licenses apply:
#
# Copyright 2020 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the License);
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an AS IS BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

project(DRMNagraSystem)

set(DRM_PLUGIN_SOURCES 
    MediaSessionSystem.cpp 
    MediaSystem.cpp
    OperatorVault.cpp
    ../ParsePSSHHeader.cpp)

find_package(Nagra QUIET)
find_package(WPEFramework QUIET)
find_package(ocdm REQUIRED)
include(interfaces OPTIONAL )
include(plugins OPTIONAL )
include(WPEFramework OPTIONAL )

set(DRMNAGRASYSTEM_INCLUDE_DIRS ${PROJECT_BINARY_DIR} )
include_directories(${NAGRA_INCLUDE_DIRS})

message(WARNING "Values: PROJECT_BINARY_DIR: ${PROJECT_BINARY_DIR}, PROJECT_NAME ${PROJECT_NAME}, NAGRA_INCLUDE_DIRS: ${NAGRA_INCLUDE_DIRS}, CMAKE_INSTALL_PREFIX= ${CMAKE_INSTALL_PREFIX} NAMESPACE= ${NAMESPACE} CMAKE_SYSROOT =${CMAKE_SYSROOT}")

message(WARNING "Values: CMAKE_MODULE_PATH: ${CMAKE_MODULE_PATH} ")
message(WARNING "Values: CMAKE_BUILDS_PATH = ${CMAKE_BUILDS_PATH} ")
message(WARNING "Values: CMAKE_SYSTEM_PATH: ${CMAKE_SYSTEM_PATH} ")
message(WARNING "Values: CMAKE_BINARY_DIR= ${CMAKE_BINARY_DIR} ")
message(WARNING "Values: INTERFACE_INCLUDE_DIRECTORIES = ${INTERFACE_INCLUDE_DIRECTORIES}")
message(WARNING "Values: INTERFACE_SYSTEM_INCLUDE_DIRECTORIES= ${INTERFACE_SYSTEM_INCLUDE_DIRECTORIES}")
message(WARNING "Values: TARGET_NAME= ${TARGET_NAME}")
message(WARNING "Values: CMAKE_SOURCE_DIR= ${CMAKE_SOURCE_DIR}")
message(WARNING "Values: CMAKE_CURRENT_SOURCE_DIR= ${CMAKE_CURRENT_SOURCE_DIR}")

message(WARNING "Yacto Values: WORKDIR: ${WORKDIR}, TOPDIR= ${TOPDIR}, STAGING_DIR: ${STAGING_DIR}, STAGING_INCDIR = ${STAGING_INCDIR}, STAGING_LIBDIR= ${STAGING_LIBDIR}, STAGING_DIR_HOST= ${STAGING_DIR_HOST}")

# Create imported target ocdm::ocdm
#add_library(ocdm::ocdm SHARED IMPORTED)

set_target_properties(ocdm::ocdm PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "${_IMPORT_PREFIX}/include/opencdm;${_IMPORT_PREFIX}/include/WPEFramework/ocdm"
  INTERFACE_LINK_LIBRARIES "WPEFrameworkCore::WPEFrameworkCore"
)
set(INCLUDE_DIR_PRIVATE
        ${CMAKE_SYSROOT}/usr/include/WPEFramework/
	${CMAKE_SYSROOT}/
	${CMAKE_CURRENT_SOURCE_DIR}/ )


include_directories( ${CMAKE_SYSROOT}/usr/include/WPEFramework/
		 	${CMAKE_SYSROOT}/
			${CMAKE_SOURCE_DIR}/
	     	)

# add the library
add_library(${PROJECT_NAME} SHARED ${DRM_PLUGIN_SOURCES})
include_directories( ${PROJECT_BINARY_DIR}/ )
#target_link_libraries(${PROJECT_NAME} ${NAGRA_LIBRARIES} ${CORE_LIBRARIES})
#add_compiler_flags(${PROJECT_NAME} "${CORE_DEFINITIONS}")
set_target_properties(${PROJECT_NAME} PROPERTIES SUFFIX ".drm")
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "")

install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/share/${NAMESPACE}/OCDM)
