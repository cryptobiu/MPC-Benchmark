
#include <stdlib.h>
#include "ProtocolParty.h"
#include "ZpKaratsubaElement.h"
#include <smmintrin.h>
#include <inttypes.h>
#include <stdio.h>
#include <x86intrin.h>



__m128 _mm_mod_ps2(const __m128& a, const __m128& aDiv){
    __m128 c = _mm_div_ps(a,aDiv);
    __m128i i = _mm_cvttps_epi32(c);
    __m128 cTrunc = _mm_cvtepi32_ps(i);
    __m128 base = _mm_mul_ps(cTrunc, aDiv);
    __m128 r = _mm_sub_ps(a, base);
    return r;
}


void mul128(__m128i a, __m128i b, __m128i *res1, __m128i *res2)
{
    __m128i tmp3, tmp4, tmp5, tmp6;

    tmp3 = _mm_clmulepi64_si128(a, b, 0x00);
    tmp4 = _mm_clmulepi64_si128(a, b, 0x10);
    tmp5 = _mm_clmulepi64_si128(a, b, 0x01);
    tmp6 = _mm_clmulepi64_si128(a, b, 0x11);

    tmp4 = _mm_xor_si128(tmp4, tmp5);
    tmp5 = _mm_slli_si128(tmp4, 8);
    tmp4 = _mm_srli_si128(tmp4, 8);
    tmp3 = _mm_xor_si128(tmp3, tmp5);
    tmp6 = _mm_xor_si128(tmp6, tmp4);
    // initial mul now in tmp3, tmp6
    *res1 = tmp3;
    *res2 = tmp6;
}


void multUlong(unsigned long a, unsigned long b, unsigned long *res1, unsigned long *res2){

    unsigned int alow = ((int*)&a)[0];
    unsigned int ahi = ((int*)&a)[1];
    unsigned int blow = ((int*)&b)[0];
    unsigned int bhi = ((int*)&b)[1];

    uint64_t    a_lo = (uint32_t)a;
    uint64_t    a_hi = a >> 32;
    uint64_t    b_lo = (uint32_t)b;
    uint64_t    b_hi = b >> 32;

    uint64_t a_x_b_hi =  ahi * b_hi;
    uint64_t a_x_b_mid = a_hi * b_lo;
    uint64_t b_x_a_mid = b_hi * a_lo;
    uint64_t a_x_b_lo =  a_lo * b_lo;


    *res1 = a_x_b_lo + ((uint64_t)(uint32_t)a_x_b_mid +
                       (uint64_t)(uint32_t)b_x_a_mid)<<32;


    unsigned long carry_bit = ((uint64_t)(uint32_t)a_x_b_mid +
                 (uint64_t)(uint32_t)b_x_a_mid +
                 (a_x_b_lo >> 32) ) >> 32;

    *res2 = a_x_b_hi +
                         (a_x_b_mid >> 32) + (b_x_a_mid >> 32) +
                         carry_bit;


}

unsigned long mersenneAdd(unsigned long high, unsigned long low){

    unsigned long low61 = (low & 2305843009213693951);
    unsigned long low61to64 = (low>>61);
    unsigned long highShift3 = (high<<3);

    unsigned long res = low61 + low61to64 + highShift3;

    if(res >= 2305843009213693951)
        res-= 2305843009213693951;

    return res;


}


void multkarm(__m128i *c1, __m128i *c0, __m128i b,
              __m128i a)
{
    __m128i t1, t2;
    *c0 = _mm_clmulepi64_si128(a, b, 0x00);
    *c1 = _mm_clmulepi64_si128(a, b, 0x11);
    t1 = _mm_shuffle_epi32(a, 0xEE);
    t1 = _mm_xor_si128(a, t1);
    t2 = _mm_shuffle_epi32(b, 0xEE);
    t2 = _mm_xor_si128(b, t2);
    t1 = _mm_clmulepi64_si128(t1, t2, 0x00);
    t1 = _mm_xor_si128(*c0, t1);
    t1 = _mm_xor_si128(*c1, t1);
    t2 = t1;
    t1 = _mm_slli_si128(t1, 8);
    t2 = _mm_srli_si128(t2, 8);
    *c0 = _mm_xor_si128(*c0, t1);
    *c1 = _mm_xor_si128(*c1, t2);

}



/**
 * The main structure of our protocol is as follows:
 * 1. Initialization Phase: Initialize some global variables (parties, field, circuit, etc).
 * 2. Preparation Phase: Prepare enough random double-sharings: a random double-sharing is a pair of
 *  two sharings of the same random value, one with degree t, and one with degree 2t. One such double-
 *  sharing is consumed for multiplying two values. We also consume double-sharings for input gates
 *  and for random gates (this is slightly wasteful, but we assume that the number of multiplication
 *  gates is dominating the number of input and random gates).
 * 3. Input Phase: For each input gate, reconstruct one of the random sharings towards the input party.
 *  Then, all input parties broadcast a vector of correction values, namely the differences of the inputs
 *  they actually choose and the random values they got. These correction values are then added on
 *  the random sharings.
 * 4. Computation Phase: Walk through the circuit, and evaluate as many gates as possible in parallel.
 *  Addition gates and random gates can be evaluated locally (random gates consume a random double-
 *  sharing). Multiplication gates are more involved: First, every party computes local product of the
 *  respective shares; these shares form de facto a 2t-sharing of the product. Then, from this sharing,
 *  a degree-2t sharing of a random value is subtracted, the difference is reconstructed and added on
 *  the degree-t sharing of the same random value.
 * 5. Output Phase: The value of each output gate is reconstructed towards the corresponding party.
 * @param argc
 * @param argv[1] = id of parties (1,...,N)
 * @param argv[2] = N: number of parties
 * @param argv[3] = path of inputs file
 * @param argv[4] = path of output file
 * @param argv[5] = path of circuit file
 * @param argv[6] = address
 * @param argv[7] = fieldType
 * @return
 */


int main(int argc, char* argv[])
{

    CmdParser parser;
    auto parameters = parser.parseArguments("", argc, argv);
    int times = stoi(parameters["internalIterationsNumber"]);
    string fieldType(parameters["fieldType"]);

    if(fieldType.compare("ZpMersenne") == 0)
    {

        ProtocolParty<ZpMersenneIntElement> protocol(argc, argv);
        auto t1 = high_resolution_clock::now();
        protocol.run();
        auto t2 = high_resolution_clock::now();

        auto duration = duration_cast<milliseconds>(t2-t1).count();
        cout << "time in milliseconds for " << times << " runs: " << duration << endl;


        cout << "end main" << '\n';

    }
    else if(fieldType.compare("ZpMersenne61") == 0)
    {

        ProtocolParty<ZpMersenneLongElement> protocol(argc, argv);
        auto t1 = high_resolution_clock::now();
        protocol.run();

        auto t2 = high_resolution_clock::now();

        auto duration = duration_cast<milliseconds>(t2-t1).count();
        cout << "time in milliseconds for " << times << " runs: " << duration << endl;

        cout << "end main" << '\n';

    }

    else if(fieldType.compare("ZpKaratsuba") == 0) {


        ProtocolParty<ZpKaratsubaElement> protocol(argc, argv);
        auto t1 = high_resolution_clock::now();
        protocol.run();
        auto t2 = high_resolution_clock::now();

        auto duration = duration_cast<milliseconds>(t2 - t1).count();
        cout << "time in milliseconds for " << times << " runs: " << duration << endl;


        cout << "end main" << '\n';
    }



    else if(fieldType.compare("GF2m") == 0){

        ProtocolParty<GF2E> protocol(argc, argv);
        auto t1 = high_resolution_clock::now();
        protocol.run();
        auto t2 = high_resolution_clock::now();

        auto duration = duration_cast<milliseconds>(t2-t1).count();
        cout << "time in milliseconds for " << times << " runs: " << duration << endl;

        cout << "end main" << '\n';
    }

    else if(fieldType.compare("Zp") == 0)
    {

        ProtocolParty<ZZ_p> protocol(argc, argv);

        auto t1 = high_resolution_clock::now();
        protocol.run();
        auto t2 = high_resolution_clock::now();

        auto duration = duration_cast<milliseconds>(t2-t1).count();
        cout << "time in milliseconds for " << times << " runs: " << duration << endl;

        cout << "end main" << '\n';

    }

    return 0;
}
