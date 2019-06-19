#!/usr/bin/env bash

# {1} - party start idx
# {2} - party end idx
# {3} - number of parties
# {4} - parties file path
# {5} - size of data


for party_idx in `seq ${1} 1 ${2}`;
do
    ./ExampleProtocol ${party_idx} ${3} ${4} ${5} &
    echo "running ${party_idx}"
done