# GMW


### INSTALLATION AND EXECUTION

In order to compile and run The GMW application:
1. Go in the GMW directory.
2. Run:
$ cmake -G "Unix Makefiles"
$ make
3. to execute run :
`./GMW -partyID [party_id] -circuitFileName [circuit_file_name] -partiesFileName [parties_file_name] -inputFileName [input_file_name] -numThreads [num_threads] -internalIterationsNumber [num_iterations]`

 for example:
 ./GMW -partyID 0 -circuitFileName NigelAes3Parties.txt -partiesFileName parties.conf -inputFileName AesInputs0.txt -numThreads 2 -internalIterationsNumber 5
 This executes party number 0 of GMW protocol with 3 parties. The circuit is aes and two threads will be created (one for each other party)

There is a script that runs all the parties at once called run_protocol.sh. It should get four parameters:
1. The first party to run
2. The last party to run
3. The name of the circuit file
4. Number of threads to use in the execution.


The output of the protocol is the values of the output wires of this party. The protocol prints it to the screen.



