#!/bin/bash
#Copyright (c) 2016 Divested Computing Group

CPPFLAGS="-D_FORTIFY_SOURCE=2"
CFLAGS="-march=native -mtune=native -O3 -pipe -fstack-protector-strong -fstack-check --param=ssp-buffer-size=4 -fPIC"
CXXFLAGS="${CFLAGS}"
LDFLAGS="-Wl,-O1,--sort-common,--as-needed,-z,relro"
g++ -std=c++0x -pthread Main.cpp -o analyze
