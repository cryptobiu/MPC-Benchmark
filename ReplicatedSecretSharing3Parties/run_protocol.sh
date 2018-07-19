#! /bin/bash
for i in `seq $1 1 $2`;
do	
	./Secret_Sharing $i $3 $4 output.txt $5 tcp://192.168.0.12:1883 ZpMensenne &
	echo "Running $i..."
done
