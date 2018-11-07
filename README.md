## MPC Benchmark

the main goal of the repository is to offer  Multi-Party Computation (MPC) protocols.

The repository contains these protocols:
*  BroadcastComm - protocol for broadcast communication
* GMW - implementation of GMW protocol
* HyperMPC
* LowCostConstantRound
* MPCHonestMajority
* MPCHonestMajorityNoTriples
* MaliciousYaoBatch
* MaliciousYaoSingleExecution
* ReplicatedSecretSharing3Parties
* ReplicatedSecretSharing3PartiesArithmetic
* SemiHonestYao

#### Installation

In order to install this repository you will need first to install [libscapi](https://github.com/cryptobiu/libscapi). Please install libscapi at your home directory (in the future we will add the feature for custom installation directory).

After you installed `libscapi` clone this repository to your home directory.

You can install all the protocols at once or install only the protocols you like.

To install all the protocols run: `cmake . && make`
To install a protocol you like run: `cd [name of the protocol] && cmake . && make`

#### Usage

For usage examples look at the `README.md` of each protocol.