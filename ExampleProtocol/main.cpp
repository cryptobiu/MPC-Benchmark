#include <iostream>
#include "ExampleProtocol.h"

using namespace std;


int main(int argc, char* argv[])
{

    ExampleProtocol p(argc, argv);
    p.run();

    return 0;
}