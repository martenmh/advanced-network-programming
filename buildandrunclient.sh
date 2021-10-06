#!/bin/sh

cp -rf ~/Documents/anp/ ~/
cd ~/anp/build/
make
cd ../
sudo cp ~/anp/lib/libanpnetstack.so /usr/local/lib/
sudo ./bin/sh-hack-anp.sh ./build/anp_client $1
