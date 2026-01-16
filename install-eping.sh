#!/bin/bash

# check connection 
echo -e "\n### check connection to GitHub.com ### \n"
if ! curl -s --head https://github.com | head -n 1 | grep "200" > /dev/null; then
    echo -e "\n### Unable to connect to GitHub.com ### "
    exit 1
fi

# install eping.py, epinga.py, esplit.py  
echo -e "\n ### download and install eping.py and epinga.py ###\n"
mkdir -p eping 

# download eping 
cd eping 
curl -O https://raw.githubusercontent.com/ewaldj/eping/main/eping.py
curl -O https://raw.githubusercontent.com/ewaldj/eping/main/epinga.py
curl -O https://raw.githubusercontent.com/ewaldj/eping/main/esplit.py
chmod +x eping.py
chmod +x epinga.py
chmod +x esplit.py 
cd ..
echo -e "\n### done - have a nice day - www.jeitler.guru ###\n" 
