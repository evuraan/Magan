#!/bin/bash  -xv
# Author: evuraan@gmail.com

mkdir -vp ../bin

gcc  ../src/magan.c -pthread -lcurl -ljson-c -o ../bin/magan-$(uname -m)
strip ../bin/magan-$(uname -m)

