
### INTRODUCTION


This package contains a wrapper for the Yao protocol in the Single-Execution setting.
The wrapped protocol was implemented by EMP (Efficient Multi-Party computation toolkit, and the implementation can be
found at https://github.com/emp-toolkit/emp-m2pc.

The protocol is based on the https://eprint.iacr.org/2016/762.pdf paper.


### INSTALLATION AND EXECUTION

1. Go in the YaoSingleExecution directory.
2. Run the make command
3. To run the program type:
`./MaliciousYaoSingleExecution -partyID [party_id] -circuitFile [circuit_file_name] -partiesFile [parties_file_name]
                       -inputFile [input_file_name] -internalIterationsNumber [#times_to_run_the_protocol]`.  
For example, in order to run p0 with aes circuit type:
`./MaliciousYaoSingleExecution -partyID 0 -circuitFile NigelAes.txt -partiesFile Parties.txt -inputFile AesInputs0.txt
 -internalIterationsNumber 5`

The output is printed to the screen at p1 side.




