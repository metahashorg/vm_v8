#!/bin/bash

cmake -DSNIPER_LIBS_PATH="~/local" -DCMAKE_BUILD_TYPE=Release ..
make --jobs=`nproc`
