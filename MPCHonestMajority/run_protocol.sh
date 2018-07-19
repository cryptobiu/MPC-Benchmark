#! /bin/bash
for i in `seq $1 1 $2`;
do	
	./MPCHonestMajority -partyID $i -numParties $3 -inputsFile $4 -outputsFile output.txt -circuitFile $5 -fieldType $6 -genRandomSharesType $7 -multType $8 -verifyType $9 -partiesFile Parties.txt -internalIterationsNumber 5 &
	echo "Running $i..."
done
