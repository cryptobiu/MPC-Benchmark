#include <iostream>
#include "include/Party.hpp"
#include "include/MPCCommunication.hpp"
#include <libscapi/include/interactive_mid_protocols/OTExtensionBristol.hpp>


int main(int argc, char* argv[])
{

    Party party(argc, argv);
    party.run();

    bitVector outputs = party.getOutput();
    cout<<"output:"<<endl;
    cout<<outputs<<endl;

}

