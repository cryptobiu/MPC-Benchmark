
#include <stdlib.h>
#include "Protocol.h"

#include "ZpKaratsubaElement.h"
#include "ZpMersenneLongElement.h"
#include "ZpMersenneIntElement.h"
#include <chrono>

using namespace std::chrono;
/**
 * Three-Party Secure Computation Based on Replicated Secret Sharing
 * @param argc
 * @param argv[1] = id of parties (1,...,N)
 * @param argv[2] = path of inputs file
 * @param argv[3] = path of output file
 * @param argv[4] = path of circuit file
 * @param argv[5] = address
 * @param argv[6] = fieldType
 * @return
 */
int main(int argc, char* argv[])
{

    if(argc != 7)
    {
        cout << "error";
        return 0;
    }

    int times = 10;
    string outputTimerFileName = string(argv[5]) + "Times" + string(argv[1]) + ".csv";
    ProtocolTimer p(times, outputTimerFileName);

    string fieldType(argv[6]);

    if(fieldType.compare("ZpMensenne") == 0)
    {
        TemplateField<ZpMersenneIntElement> *field = new TemplateField<ZpMersenneIntElement>(2147483647);

        // 1- id, 2-input file, 3- outputfile, 4- circuitfile, 5-address,
        string a = argv[2];
        string b = argv[3];
        string c = argv[4];
        string d = argv[5];
        cout << a <<" " << b << " " << c << " " << d << endl;

        Protocol<ZpMersenneIntElement> protocol(atoi(argv[1]), field, a, b, c, d, &p);
        auto t1 = high_resolution_clock::now();
        for(int i=0; i<times; i++) {
            protocol.run(i);
        }
        auto t2 = high_resolution_clock::now();

        auto duration = duration_cast<milliseconds>(t2-t1).count();
        cout << "time in milliseconds for " << times << " runs: " << duration << endl;

        p.writeToFile();

        cout << "end main" << '\n';

        delete field;
    }

    if(fieldType.compare("ZpMensenne61") == 0)
    {
        TemplateField<ZpMersenneLongElement> *field = new TemplateField<ZpMersenneLongElement>(0);

        // 1- id, 2-input file, 3- outputfile, 4- circuitfile, 5-address,
        string a = argv[2];
        string b = argv[3];
        string c = argv[4];
        string d = argv[5];
        cout << a <<" " << b << " " << c << " " << d << endl;

        Protocol<ZpMersenneLongElement> protocol(atoi(argv[1]), field, a, b, c, d, &p);
        auto t1 = high_resolution_clock::now();
        for(int i=0; i<times; i++) {
            protocol.run(i);
        }
        auto t2 = high_resolution_clock::now();

        auto duration = duration_cast<milliseconds>(t2-t1).count();
        cout << "time in milliseconds for " << times << " runs: " << duration << endl;

        p.writeToFile();

        cout << "end main" << '\n';

        delete field;
    }

    if(fieldType.compare("GF2m") == 0)
    {
        TemplateField<GF2E> *field = new TemplateField<GF2E>(8);

        Protocol<GF2E> protocol(atoi(argv[1]),field, argv[2], argv[3], argv[4], argv[5], &p);
        auto t1 = high_resolution_clock::now();
        for(int i=0; i<times; i++) {
            protocol.run(i);
        }
        auto t2 = high_resolution_clock::now();

        auto duration = duration_cast<milliseconds>(t2-t1).count();
        cout << "time in milliseconds for " << times << " runs: " << duration << endl;

        p.writeToFile();

        cout << "end main" << '\n';

        delete field;
    }

    if(fieldType.compare("Zp") == 0)
    {
        TemplateField<ZZ_p> * field = new TemplateField<ZZ_p>(2147483647);

        Protocol<ZZ_p> protocol(atoi(argv[1]),field, argv[2], argv[3], argv[4], argv[5], &p);

        auto t1 = high_resolution_clock::now();
        for(int i=0; i<times; i++) {
            protocol.run(i);
        }
        auto t2 = high_resolution_clock::now();

        auto duration = duration_cast<milliseconds>(t2-t1).count();
        cout << "time in milliseconds for " << times << " runs: " << duration << endl;

        p.writeToFile();

        cout << "end main" << '\n';

        delete field;

    }

    if(fieldType.compare("ZpKaratsuba") == 0)
    {
        TemplateField<ZpKaratsubaElement> *field = new TemplateField<ZpKaratsubaElement>(0);

        Protocol<ZpKaratsubaElement> protocol(atoi(argv[1]),field, argv[2], argv[3], argv[4], argv[5], &p);

        auto t1 = high_resolution_clock::now();
        for(int i=0; i<times; i++) {
            protocol.run(i);
        }
        auto t2 = high_resolution_clock::now();

        auto duration = duration_cast<milliseconds>(t2-t1).count();
        cout << "time in milliseconds for " << times << " runs: " << duration << endl;

        p.writeToFile();

        cout << "end main" << '\n';

        delete field;

    }

    return 0;
}
