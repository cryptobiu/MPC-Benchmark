A Framework for Constructing Fast MPC over Arithmetic Circuits with Malicious Adversaries and an Honest-Majority∗

Yehuda Lindell
Bar-Ilan University
Yehuda.Lindell@biu.ac.il

Ariel Nof
Bar-Ilan University
ariel.nof@biu.ac.il

https://eprint.iacr.org/2017/816.pdf

ABSTRACT
Protocols for secure multiparty computation enable a set of parties
to compute a function of their inputs without revealing anything
but the output. The security properties of the protocol must be
preserved in the presence of adversarial behavior. The two classic
adversary models considered are semi-honest (where the adversary
follows the protocol specication but tries to learn more than allowed
by examining the protocol transcript) and malicious (where
the adversary may follow any arbitrary attack strategy). Protocols
for semi-honest adversaries are often far more ecient, but in many
cases the security guarantees are not strong enough.
In this paper, we present a new ecient method for “compiling”
a large class of protocols that are secure in the presence of semihonest
adversaries into protocols that are secure in the presence
of malicious adversaries. Our method assumes an honest majority
(i.e., that t < n/2 where t is the number of corrupted parties and n
is the number of parties overall), and is applicable to many semihonest
protocols based on secret-sharing. In order to achieve high
eciency, our protocol is secure with abort and does not achieve
fairness, meaning that the adversary may receive output while the
honest parties do not.
We present a number of instantiations of our compiler, and obtain
protocol variants that are very ecient for both a small and
large number of parties. We implemented our protocol variants and
ran extensive experiments to compare them with each other. Our
results show that secure computation with an honest majority can
be practical, even with security in the presence of malicious adversaries.
For example, we securely compute a large arithmetic circuit
of depth 20 with 1,000,000 multiplication gates, in approximately
0.5 seconds with three parties, and approximately 29 seconds with
50 parties, and just under 1 minute with 90 parties.
