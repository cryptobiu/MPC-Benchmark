//
// Created by hila on 05/05/17.
//

#include "ZpKaratsubaElement.h"
#include "gmp.h"


unsigned long p = 1071482619497;



ZpKaratsubaElement::ZpKaratsubaElement()
{
    elem = 0;
}

ZpKaratsubaElement::ZpKaratsubaElement(long elem)
{

    if(elem>=0 && elem<p){
        this->elem = elem;
    }
    else {
        this->elem = elem % p;

    }
}

ZpKaratsubaElement ZpKaratsubaElement::operator+(const ZpKaratsubaElement& f2)
{
    ZpKaratsubaElement answer;

    answer.elem = (elem + f2.elem);

    if(answer.elem>=p)
        answer.elem-=p;

    return answer;
}


ZpKaratsubaElement& ZpKaratsubaElement::operator+=(const ZpKaratsubaElement& f2){

    elem += f2.elem;

    if(elem>=p)
        elem-=p;
    return *this;

}

ZpKaratsubaElement ZpKaratsubaElement::operator-(const ZpKaratsubaElement& f2)
{
    ZpKaratsubaElement answer;

    long temp =  (long)elem - (long)f2.elem;

    if(temp<0){
        answer.elem = temp + p;
    }
    else{
        answer.elem = temp;
    }

    return answer;
}

ZpKaratsubaElement ZpKaratsubaElement::operator*(const ZpKaratsubaElement& f2)
{
    ZpKaratsubaElement answer;

    unsigned long result;
    if(f2.elem< 8388608 || elem<8388608) {
        answer.elem = (f2.elem * elem);

        if (answer.elem > p)
            answer.elem = answer.elem % p;
    }
    else {

        unsigned long x1 = elem >> 9; // the top 56 bit (should be only 32 bit)
        unsigned long y1 = f2.elem >> 9;

        unsigned long x0 = elem & (512-1);
        unsigned long y0 = f2.elem & (512-1);

        unsigned long u0 = (x1 * y1)%p;

        unsigned long w0 = x0 * y0;

        long intermediate = ((u0 << 9) + (u0 << 18)) - ((((x1 - x0) * (y1 - y0)) % p) << 9);

        if(intermediate<0){

            intermediate = intermediate % (long)p;

            result = intermediate + p + ((w0 << 9) + w0);

            if(result>=p)
                result-=p;

            // mod p
            answer.elem = result;

        }
        else {

            // mod p
            answer.elem = (intermediate + ((w0 << 9) + w0)) % p;
        }
    }
    return answer;

}



ZpKaratsubaElement& ZpKaratsubaElement::operator*=(const ZpKaratsubaElement& f2){

    unsigned long result;
    if(f2.elem< 8388608 || elem<8388608) {
        elem = (f2.elem * elem);

        if (elem > p)
            elem = elem % p;
    }
    else {

        unsigned long x1 = elem >> 9; // the top 56 bit (should be only 32 bit)
        unsigned long y1 = f2.elem >> 9;

        unsigned long x0 = elem & (512-1);
        unsigned long y0 = f2.elem & (512-1);

        unsigned long u0 = (x1 * y1)%p;

        unsigned long w0 = x0 * y0;

        long intermediate = ((u0 << 9) + (u0 << 18)) - ((((x1 - x0) * (y1 - y0)) % p) << 9);

        if(intermediate<0){

            intermediate = intermediate % (long)p;

            result = intermediate + p + ((w0 << 9) + w0);

            if(result>=p)
                result-=p;

            // mod p
            elem = result;

        }
        else {

            // mod p
            elem = (intermediate + ((w0 << 9) + w0)) % p;
        }
    }

    return *this;

}



ZpKaratsubaElement& ZpKaratsubaElement::operator=(const ZpKaratsubaElement& other) // copy assignment
{
    if (this != &other) { // self-assignment check expected
        elem = other.elem;
    }
    return *this;
}

/**
 * Euclid's extended algorithm:
 * ax + by = gcd(a,b)
 */
void gcd (unsigned long a, unsigned long b, unsigned long& gcd, unsigned long& x, unsigned long& y) {

    x = 0, y = 1;
    unsigned long u = 1, v = 0, m, n, q, r;
    gcd = b;
    while (a != 0) {
        q = gcd / a;
        r = gcd % a;
        m = x - u * q;
        n = y - v * q;
        gcd = a;
        a = r;
        x = u;
        y = v;
        u = m;
        v = n;
    }
}

/**
 * Modular division:
 * find z such that: z * B mod m == A.
 * If there is more than one (i.e. when gcd(B,m)>1) - returns the smallest such integer
 */
ZpKaratsubaElement ZpKaratsubaElement::operator/(const ZpKaratsubaElement& f2)
{

    ZpKaratsubaElement answer;
    mpz_t d;
    mpz_t result;
    mpz_t mpz_elem;
    mpz_t mpz_me;
    mpz_init_set_str (d, "1071482619497", 10);
    mpz_init(mpz_elem);
    mpz_init(mpz_me);


    //mpz_init_set(mpz_elem, f2.elem);
    //mpz_init_set(mpz_me, elem);

    mpz_set_ui(mpz_elem, f2.elem);
    mpz_set_ui(mpz_me, elem);

    mpz_init(result);

    mpz_invert ( result, mpz_elem, d );

    mpz_mul (result, result, mpz_me);
    mpz_mod (result, result, d);


    answer.elem = mpz_get_ui(result);


    return answer;

}