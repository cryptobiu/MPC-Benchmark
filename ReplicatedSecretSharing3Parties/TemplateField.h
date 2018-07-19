//
// Created by meital on 15/11/16.
//

#ifndef SECRET_SHARING_TEMPLATEFIELD_H
#define SECRET_SHARING_TEMPLATEFIELD_H


#include "AES_PRG.h"
#include <stdint.h>
#include <bitset>
#include <sstream>
#include <NTL/GF2E.h>
#include <NTL/GF2X.h>
#include <NTL/ZZ_p.h>
#include<NTL/GF2XFactoring.h>



template <class FieldType>
class TemplateField {
private:

    long fieldParam;
    int elementSizeInBytes;
    FieldType* m_ZERO;
    FieldType* m_ONE;
public:


    /**
     * the function create a field by:
     * generate the irreducible polynomial x^8 + x^4 + x^3 + x + 1 to work with
     * init the field with the newly generated polynomial
     */
    TemplateField(long fieldParam);

    /**
     * return the field
     */

    string elementToString(const FieldType &element);
    FieldType stringToElement(const string &str);

    void elementToBytes(unsigned char* output,FieldType &element);
    FieldType bytesToElement(unsigned char* elemenetInBytes);


    FieldType* GetZero();
    FieldType* GetOne();

    int getElementSizeInBytes(){ return elementSizeInBytes;}
    /*
     * The i-th field element. The ordering is arbitrary, *except* that
     * the 0-th field element must be the neutral w.r.t. addition, and the
     * 1-st field element must be the neutral w.r.t. multiplication.
     */
    FieldType GetElement(long b);
    FieldType Random();
    ~TemplateField();

};



template <class FieldType>
string TemplateField<FieldType>::elementToString(const FieldType& element)
{
    ostringstream stream;
    stream << element;
    string str =  stream.str();
    return str;
}


template <class FieldType>
FieldType TemplateField<FieldType>::stringToElement(const string &str) {

    FieldType element;

    istringstream iss(str);
    iss >> element;

    return element;
}




/**
 * A random random field element, uniform distribution
 */
template <class FieldType>
FieldType TemplateField<FieldType>::Random() {
    PRG & prg = PRG::instance();
    long b = prg.getRandom();

    return GetElement(b);
}

template <class FieldType>
FieldType* TemplateField<FieldType>::GetZero()
{
    return m_ZERO;
}

template <class FieldType>
FieldType* TemplateField<FieldType>::GetOne()
{
    return m_ONE;
}


template <class FieldType>
TemplateField<FieldType>::~TemplateField() {
    delete m_ZERO;
    delete m_ONE;
}




#endif //SECRET_SHARING_TEMPLATEFIELD_H