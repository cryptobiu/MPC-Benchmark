
#!/usr/bin/env bash

for i in `seq $1 1 $2`;
do
	./LowCostConstantRoundShortKeysMPC -partyID ${i} -circuitFile ${3} -partiesFile ${5} -keySize ${4} -isLookup ${6} -inputsFile ${7} -otherInputFileName ${8} -internalIterationsNumber ${9} &

	echo "Running $i..."
done