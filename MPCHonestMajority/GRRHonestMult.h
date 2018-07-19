//
// Created by meital on 18/04/17.
//

#include "HonestMultAbstract.h"

#ifndef MPCHONESTMAJORITY_GRRHONESTMULT_H
#define MPCHONESTMAJORITY_GRRHONESTMULT_H

#endif //MPCHONESTMAJORITY_GRRHONESTMULT_H

template <typename FieldType>
class GRRHonestMult : public HonestMultAbstract<FieldType> {

private:
    ProtocolParty<FieldType> *protocol;
public:

    GRRHonestMult(ProtocolParty<FieldType> *protocol) : protocol(protocol) {};

    void invokeOffline() {};

    void mult(FieldType *a, FieldType *b, vector <FieldType> &cToFill, int numOfTrupples);
};



template <class FieldType>
void GRRHonestMult<FieldType>::mult(FieldType *a, FieldType *b, vector<FieldType> &cToFill, int numOfTrupples)
{

    vector<FieldType> x1(protocol->N),y1(protocol->N);

    vector<vector<FieldType>> sendBufsElements(protocol->N);
    vector<vector<byte>> sendBufsBytes(protocol->N);
    vector<vector<byte>> recBufsBytes(protocol->N);

    FieldType d;

    vector<FieldType> ReconsBuf(numOfTrupples);


    for(int i=0; i < protocol->N; i++)
    {
        sendBufsElements[i].resize(numOfTrupples);
        sendBufsBytes[i].resize((numOfTrupples)*protocol->field->getElementSizeInBytes());
        recBufsBytes[i].resize((numOfTrupples)*protocol->field->getElementSizeInBytes());
    }


    for(int k = 0; k < numOfTrupples ; k++)//go over only the logit gates
    {

        //set the secret of the polynomial to be the multiplication of the shares
        x1[0] = a[k] * b[k];

        // generate random degree-T polynomial
        for(int i = 1; i < protocol->T+1; i++)
        {
            // A random field element, uniform distribution
            x1[i] = protocol->field->Random();

        }

        protocol->matrix_vand.MatrixMult(x1, y1, protocol->T+1); // eval poly at alpha-positions

        // prepare shares to be sent
        for(int i=0; i < protocol->N; i++)
        {
            //cout << "y1[ " <<i<< "]" <<y1[i] << endl;
            sendBufsElements[i][k] = y1[i];
        }

    }

    //convert to bytes
    int fieldByteSize = protocol->field->getElementSizeInBytes();
    for(int i=0; i < protocol->N; i++)
    {
        for(int j=0; j<sendBufsElements[i].size();j++) {
            protocol->field->elementToBytes(sendBufsBytes[i].data() + (j * fieldByteSize), sendBufsElements[i][j]);
        }
    }

    protocol->roundFunctionSync(sendBufsBytes, recBufsBytes,4);

    int fieldBytesSize = protocol->field->getElementSizeInBytes();

    for(int k = 0; k < numOfTrupples ; k++) {

        // generate random degree-T polynomial
        for (int i = 0; i < protocol->N; i++) {
            x1[i] = protocol->field->bytesToElement(recBufsBytes[i].data() + (k * fieldBytesSize));
        }

        FieldType accum = *protocol->field->GetZero();
        for (int i = 0; i < protocol->N; i++) {

            accum += protocol->firstRowVandInverse[i] * x1[i];

        }

        cToFill[k] = accum;
    }

}


