#!/bin/sh


rm -Rf build
mkdir build
cd build
cmake ../ -DCMAKE_BUILD_TYPE=Debug
make -j `nproc` || exit 1
cd ..
echo "Build was made in build/ directory"
