#!/usr/bin/env bash

for i in `seq $1 1 $2`;
do
	./LowCostConstantRoundMPC -partyID $i -circuitFile $3 -partiesFile $4 -inputsFile "AesInputs$i.txt" -numThreads $5 -B $6 -internalIterationsNumber $7 &
	echo "Running $i..."
done
