## SemiHonestYao

### INTRODUCTION

This protocol is an implementation of Yao protocol.

Yao’s basic protocol is secure against semi-honest adversaries and is extremely efficient in terms of number of rounds,
which is constant, and independent of the target function being evaluated.
The function is viewed as a Boolean circuit, with inputs in binary of fixed length.

Yao explained how to garble a circuit (hide its structure) so that two parties, sender and receiver, can learn the
output of the circuit and nothing else.
At a high level, the sender prepares the garbled circuit and sends it to the receiver, then they execute an OT protocol
in order to let the receiver know the garbled values of his inputs without the sender reveals the receiver's boolean inputs.
Then the receiver evaluates the circuit and gets the output.

### INSTALLATION AND EXECUTION

1. Go in the SemiHonestYao directory.
2. Run the `cmake . && make` command
3. In order to execute the sender run  `./SemiHonestYao -partyID 0 -configFile YaoConfig.txt -partiesFile Parties -internalIterationsNumber 1`
   In order to execute the receiver run `./SemiHonestYao -partyID 1 -configFile YaoConfig.txt -partiesFile Parties -internalIterationsNumber 1`







