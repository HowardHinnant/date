#!/bin/sh

# show what is to be run
echo $1
# run the command
eval $1 || exit 1 # if fails, return 1
