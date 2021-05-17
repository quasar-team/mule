#!/bin/bash
#
# This script is used to configure Mule's dependencies for usage with
# LCG resources over CVMFS or in CC7 natively.
# 
# Please ensure that virtualenv is installed
#
# Author: Paris Moschovakos (paris.moschovakos@cern.ch)
# Date:   20-04-2020

gccVersion() {
  # GCC version
  currentVersion="$($CC --version | head -n1 | cut -d" " -f3)"
  echo -e "${green}Info:${normalColor} GCC version is" $(tput bold)$currentVersion$(tput sgr0)
}

cmakeVersion() {
  # CMake version
  if [ -f /usr/bin/cmake ]; then
    currentVersion="$(cmake --version | head -n1 | cut -d" " -f3)"
    echo -e "${green}Info:${normalColor} CMake version is" $(tput bold)$currentVersion$(tput sgr0)
  fi
}

isCentOS() {
  # Check if we are on compatible operating system (CentOS)
  grep -e "CentOS" /etc/redhat-release &> /dev/null
  if [ $? -eq 0 ]; then
    echo "We are in CentOS"
    return 0
  else
    echo "Not compatible OS. Please only use CentOS 7. Aborting..."
    return 1
  fi
}

# CentOS local setup (default)
if isCentOS; then

  if [ -d "/cvmfs/sft.cern.ch/lcg" ]; then
    #	CVMFS setup | Using newer gcc from LCG
    echo "Resolving dependencies from CVMFS..."

    # Sourcing binutils which also take care of the gcc
    source /cvmfs/sft.cern.ch/lcg/contrib/gcc/8binutils/x86_64-centos7/setup.sh

    # Providing BOOST ROOT path. It should be compatible with the g++ above
    export BOOST_ROOT=/cvmfs/sft.cern.ch/lcg/releases/LCG_100/Boost/1.75.0/x86_64-centos7-gcc8-opt/

    # Prociding the OPCUA TOOLKIT path. It should be compatible with the g++ above
    export OPCUA_TOOLKIT_PATH=/opt/uasdk-1.6.5-gcc83
  else
    #	CentOS local setup | Using gcc4.8.5
    echo "Resolving dependencies from within CC7 native tools..."

    export CXX=/usr/bin/g++
    export CC=/usr/bin/gcc
    export LD_LIBRARY_PATH=/usr/lib64:$LD_LIBRARY_PATH

    unset BOOST_ROOT
    export NETSNMP_LIBS="-lnetsnmp"
  fi

  echo "C++ compiler, CMake, boost and other dependencies configured"

  gccVersion
  cmakeVersion

fi
