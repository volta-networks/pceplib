#!/bin/bash
#set -x
echo "##########################################"
echo "### START Running Install   ##############"
echo "##########################################"
sudo apt update
sudo apt install gcovr -y
sudo apt install python3-lxml -y
echo "##########################################"
echo "### END   Running Install   ##############"
echo "##########################################"
