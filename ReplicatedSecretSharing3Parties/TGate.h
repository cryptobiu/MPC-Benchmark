//
// Created by hila on 15/09/16.
//

#ifndef TGATE_H_
#define TGATE_H_

/**
* The Gate class is a software representation of a circuit's gate, that is the structure of the aryhtmetic circuit and not the actuall values assigned.
* It contains a type that performs a logical function on the values of the input wires (input1 and input2)  and assigns
* that value to the output wire for multiplication and addition gates. The gates may also be of type input/output and for these gates
* there is the party attribute that represents the owner.
*
*/

#define INPUT 0
#define OUTPUT 3
#define ADD 1
#define MULT 2
#define RANDOM 4
#define SCALAR 5
#define SUB 6

struct TGate
{
    int input1;//the 0-gate index, relevant for addition/multiplication/output
    int input2;//the 1-gate index, relevant for addition/multiplication
    int output;//the output index of this gate, relevant for input/addition/multiplication
    int gateType; //the type of the gate, can be logical, that is, multiplication or addition or an input/output gate.
    int party;//the owner of the gate, relevant for input/output gate
};

#endif /* TGATE_H_ */