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

    #  First the compiler
		if [ -e /cvmfs/sft.cern.ch/lcg/contrib/gcc/9.2.0/x86_64-centos7/setup.sh ]; then
    		# source /cvmfs/sft.cern.ch/lcg/contrib/gcc/9.2.0/x86_64-centos7/setup.sh
        source /cvmfs/sft.cern.ch/lcg/contrib/gcc/8.3.0/x86_64-centos7/setup.sh
        # source /cvmfs/sft.cern.ch/lcg/contrib/gcc/6.2.0/x86_64-centos7/setup.sh
		fi
    #  Then CMake
		if [ -e /cvmfs/sft.cern.ch/lcg/releases/LCG_97/CMake/3.14.3/x86_64-centos7-gcc9-opt/CMake-env.sh ]; then
			# source /cvmfs/sft.cern.ch/lcg/releases/LCG_97/CMake/3.14.3/x86_64-centos7-gcc9-opt/CMake-env.sh
      source /cvmfs/sft.cern.ch/lcg/releases/LCG_97/CMake/3.14.3/x86_64-centos7-gcc8-opt/CMake-env.sh
      # source /cvmfs/sft.cern.ch/lcg/releases/LCG_87/CMake/3.5.2/x86_64-centos7-gcc62-opt/CMake-env.sh
      echo "CMake, configured successfully!"
		fi
    #  Then point to boost
    # export BOOST_ROOT="/cvmfs/sft.cern.ch/lcg/releases/Boost/1.72.0-d1982/x86_64-centos7-gcc9-opt"
    export BOOST_ROOT="/cvmfs/sft.cern.ch/lcg/releases/Boost/1.72.0-d1982/x86_64-centos7-gcc8-opt"
    # export BOOST_ROOT="/cvmfs/sft.cern.ch/lcg/releases/LCG_87/Boost/1.62.0/x86_64-centos7-gcc62-opt"
    #  Anything else?
    export NETSNMP_HEADERS=
    export NETSNMP_LIBS_DIRECTORIES=
    export NETSNMP_LIBS="-lnetsnmp"
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

  # The following lines are used to create a virtual environment for your python
  # and include the relevant python dependencies

  #virtualenv pythonEnvironment
  #source pythonEnvironment/bin/activate
  #pip install --upgrade pip
  #pip install -r requirements.txt

  #echo "Python dependencies configured successfully!"

  gccVersion
  cmakeVersion

fi
