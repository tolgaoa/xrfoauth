#! /bin/bash

rm -rf build/
mkdir build
cd build 
cmake ..
make -j20
cp ../prv_xapp ../prv_xrf ../pub_xapp ../pub_xrf .
