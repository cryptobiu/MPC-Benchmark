### Fast Large-Scale Honest-Majority MPC for Malicious Adversaries

The repository implements the Fast Large-Scale Honest-Majority MPC for Malicious Adversaries [article](https://eprint.iacr.org/2018/570.pdf).  

##### Abstract

Abstract. Protocols for secure multiparty computation enable a set of
parties to compute a function of their inputs without revealing anything
but the output. The security properties of the protocol must be preserved
in the presence of adversarial behavior. The two classic adversary
models considered are semi-honest (where the adversary follows the protocol
specification but tries to learn more than allowed by examining
the protocol transcript) and malicious (where the adversary may follow
any arbitrary attack strategy). Protocols for semi-honest adversaries are
often far more efficient, but in many cases the security guarantees are
not strong enough.
In this paper, we present new protocols for securely computing any functionality
represented by an arithmetic circuit. We utilize a new method
for verifying that the adversary does not cheat, that yields a cost of
just twice that of semi-honest protocols in some settings. Our protocols
are information-theoretically secure in the presence of a malicious adversaries,
assuming an honest majority. We present protocol variants for
small and large fields, and show how to efficiently instantiate them based
on replicated secret sharing and Shamir sharing. As with previous works
in this area aiming to achieve high efficiency, our protocol is secure with
abort and does not achieve fairness, meaning that the adversary may
receive output while the honest parties do not.
We implemented our protocol and ran experiments for different numbers
of parties, different network configurations and different circuit depths.
Our protocol significantly outperforms the previous best for this setting
(Lindell and Nof, CCS 2017); for a large number of parties, our implementation
runs almost an order of magnitude faster than theirs.




##### Installation

The protocol written in c++ and uses c++11 standard. It uses [libscapi](https://github.com/cryptobiu/libscapi).  
For `libscapi` installation instructions, visit [here](https://github.com/cryptobiu/libscapi/blob/master/build_scripts/INSTALL.md).  
After you installed `libscapi`, run `cmake . && make`

##### Usage

The protocol designed for at least 3 parties.
To run the the protocol open a terminal and run:  
`run_protocol.sh <min_party_id> <max_party_id> <number_of_parties> <input_file> <circuit_file> <filed type> <parties_file> <number_of_iterations>` 

* field_type can be one of this values:
    * ZpMersenne31
    * ZpMersenne61
    * ZpKaratsuba
    * GF2m
    * Zp

* parties_file - a file that contains the ip addresses and the port of all the parties. An example file can be found [here](../master/Parties.txt).
    