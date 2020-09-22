#!/bin/bash
sudo apt-get install unzip unrar p7zip-full
python3 -m pip install patool
python3 -m pip install pyunpack
sudo apt install build-essential
sudo apt-get install manpages-dev
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-9 90 --slave /usr/bin/g++ g++ /usr/bin/g++-9 --slave /usr/bin/gcov gcov /usr/bin/gcov-9
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-7 70 --slave /usr/bin/g++ g++ /usr/bin/g++-7 --slave /usr/bin/gcov gcov /usr/bin/gcov-7
sudo apt-get install -y tshark
sudo apt-get install tcpflow
