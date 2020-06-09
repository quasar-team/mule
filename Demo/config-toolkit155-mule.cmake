# @author:     Paris Moschovakos <paris.moschovakos@cern.ch>
# 
# @copyright:  2020 CERN
# 
# @license:
# LICENSE:
# Copyright (c) 2020, CERN
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT  HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS  OR IMPLIED  WARRANTIES, INCLUDING, BUT NOT  LIMITED TO, THE IMPLIED
# WARRANTIES  OF  MERCHANTABILITY  AND  FITNESS  FOR  A  PARTICULAR  PURPOSE  ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL,  SPECIAL, EXEMPLARY, OR  CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT  NOT LIMITED TO,  PROCUREMENT OF  SUBSTITUTE GOODS OR  SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS  INTERRUPTION) HOWEVER CAUSED AND ON
# ANY  THEORY  OF  LIABILITY,   WHETHER IN  CONTRACT, STRICT  LIABILITY,  OR  TORT
# (INCLUDING  NEGLIGENCE OR OTHERWISE)  ARISING IN ANY WAY OUT OF  THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

message(STATUS "Using file [config-toolkit155-mule.cmake] toolchain file")

set(CMAKE_CXX_COMPILER $ENV{CXX})
set(CMAKE_CC_COMPILER $ENV{CC})

# ---------------
# Mule
# ---------------
set(MULE_INCLUDE_DIRECTORIES ${PROJECT_SOURCE_DIR}/Mule/include)
set(MULE_LINK_DIRECTORIES)
set(MULE_LINK_LIBRARIES)

message(STATUS "Taking Mule dependencies from environment:")
message(STATUS "Mule headers [${MULE_INCLUDE_DIRECTORIES}]")
message(STATUS "Mule lib directories [${MULE_LINK_DIRECTORIES}]")
message(STATUS "Mule libs [${MULE_LINK_LIBRARIES}]")

# -------
# Net-SNMP - use the one defined for Mule by sourcing setupEnvironment.sh
# -------
set(NETSNMP_INCLUDE_DIRECTORIES $ENV{NETSNMP_HEADERS})
set(NETSNMP_LINK_DIRECTORIES $ENV{NETSNMP_LIB_DIRECTORIES})
set(NETSNMP_LINK_LIBRARIES $ENV{NETSNMP_LIBS})

message(STATUS "Taking Net-SNMP dependencies from environment:")
message(STATUS "Net-SNMP headers [${NETSNMP_INCLUDE_DIRECTORIES}]")
message(STATUS "Net-SNMP lib directories [${NETSNMP_LINK_DIRECTORIES}]")
message(STATUS "Net-SNMP libs [${NETSNMP_LINK_LIBRARIES}]")

# -------
# Boost - use the one defined for Mule by sourcing setupEnvironment.sh
# -------
set ( BOOST_ROOT $ENV{BOOST_ROOT} )

message(STATUS "Taking Boost dependencies from environment:")
message(STATUS "Boost root [${BOOST_ROOT}]")

# -------
# OPC UA
# -------
if(DEFINED ENV{OPCUA_TOOLKIT_PATH})
  set(OPCUA_TOOLKIT_PATH $ENV{OPCUA_TOOLKIT_PATH})
  message(
    STATUS
      "Taking OPC UA Toolkit path from the environment: ${OPCUA_TOOLKIT_PATH}")
else(DEFINED ENV{OPCUA_TOOLKIT_PATH})
  set(OPCUA_TOOLKIT_PATH "/opt/uasdk-1.5.5-gcc62")
  message(
    STATUS
      "Taking OPC UA Toolkit path from the CMake config file: ${OPCUA_TOOLKIT_PATH}"
  )
endif(DEFINED ENV{OPCUA_TOOLKIT_PATH})

set(OPCUA_TOOLKIT_LIBS_DEBUG
    "-luamoduled -lcoremoduled -luabased -luastackd -luapkid -lxmlparserd -lxml2 -lssl -lcrypto -lpthread -lrt"
)
set(OPCUA_TOOLKIT_LIBS_RELEASE
    "-luamodule -lcoremodule -luabase -luastack -luapki -lxmlparser -lxml2 -lssl -lcrypto -lpthread -lrt"
)

include_directories(
  ${OPCUA_TOOLKIT_PATH}/include/uastack ${OPCUA_TOOLKIT_PATH}/include/uabase
  ${OPCUA_TOOLKIT_PATH}/include/uaserver ${OPCUA_TOOLKIT_PATH}/include/uapki
  ${OPCUA_TOOLKIT_PATH}/include/xmlparser)

add_custom_target(quasar_opcua_backend_is_ready)

# ----- XML Libs -----

set(XML_LIBS -lxerces-c)

# -----
# General settings
# -----

add_definitions(-Wall -DBACKEND_UATOOLKIT  -Wno-deprecated)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)