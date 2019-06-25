#!/usr/bin/env bash

# install relic
git clone https://github.com/relic-toolkit/relic.git
cd relic
cmake -DALIGN=16 -DARCH=X64 -DARITH=curve2251-sse -DCHECK=off -DFB_POLYN=251 \
 -DFB_METHD="INTEG;INTEG;QUICK;QUICK;QUICK;QUICK;LOWER;SLIDE;QUICK" -DFB_PRECO=on \
  -DFB_SQRTF=off -DEB_METHD="PROJC;LODAH;COMBD;INTER" -DEC_METHD="CHAR2" \
  -DCOMP="-O3 -funroll-loops -fomit-frame-pointer -march=native -msse4.2 -mpclmul" \
  -DTIMER=CYCLE -DWITH="MD;DV;BN;FB;EB;EC" -DWSIZE=64 .
make
sudo make install
cd ..

# install emp-tool
git clone https://github.com/emp-toolkit/emp-tool.git
cd emp-tool
cmake .
make
sudo make install
cd ..

# install emp-ot
git clone https://github.com/emp-toolkit/emp-ot.git
cd emp-ot
cmake .
make
sudo make install
cd ..

# install emp-m2pc
git clone https://github.com/emp-toolkit/emp-m2pc.git
cd emp-m2pc
cmake .
make
cd ..

mkdir -p ~/EMP
mv emp-* ~/EMP