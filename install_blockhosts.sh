#!/bin/bash
#-- install script for blockhosts
#-- pgpx.io
echo ""
echo ""
echo " ppppp   ppppppppp      ggggggggg   ggggg"
echo " p::::ppp:::::::::p    g:::::::::ggg::::g"
echo " p:::::::::::::::::p  g:::::::::::::::::g"
echo " pp::::::ppppp::::::pg::::::ggggg::::::gg"
echo "  p:::::p     p:::::pg:::::g     g:::::g "
echo "  p:::::p     p:::::pg:::::g     g:::::g "
echo "  p:::::p     p:::::pg:::::g     g:::::g "
echo "  p:::::p    p::::::pg::::::g    g:::::g "
echo "  p:::::ppppp:::::::pg:::::::ggggg:::::g "
echo "  p::::::::::::::::p  g::::::::::::::::g "
echo "  p::::::::::::::pp    gg::::::::::::::g "
echo "  p::::::pppppppp        gggggggg::::::g "
echo "  p:::::p                        g:::::g "
echo "  p:::::p            gggggg      g:::::g "
echo " p:::::::p           g:::::gg   gg:::::g "
echo " p:::::::p            g::::::ggg:::::::g "
echo " p:::::::p             gg:::::::::::::g  "
echo " ppppppppp               ggg::::::ggg    "
echo "                            gggggg       "
echo ""
echo ""
echo " need support? https://palner.com"
echo ""
echo "Copyright (c) 2024 Fred Posner"
echo "Copyright (c) 2024 The Palner Group, Inc."
echo ""
echo "Permission is hereby granted, free of charge, to any person obtaining a copy"
echo "of this software and associated documentation files (the "Software"), to deal"
echo "in the Software without restriction, including without limitation the rights"
echo "to use, copy, modify, merge, publish, distribute, sublicense, and/or sell"
echo "copies of the Software, and to permit persons to whom the Software is"
echo "furnished to do so, subject to the following conditions:"
echo ""
echo "The above copyright notice and this permission notice shall be included in all"
echo "copies or substantial portions of the Software."
echo ""
echo "THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR"
echo "IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,"
echo "FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE"
echo "AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER"
echo "LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,"
echo "OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE"
echo "SOFTWARE."
echo ""

#-- download binary and config to /usr/local/bin
echo ""
if [ -d "/usr/local/bin" ]
then
 echo "[-] moving into /usr/local/bin/"
 cd /usr/local/bin
else
 echo "[X] /usr/local/bin/ does not exist"
 exit 1
fi

echo "[-] downloading latest blockhosts from github"
wget https://github.com/palner/blockhosts/raw/refs/heads/main/binary/blockhosts &>/dev/null
if [ "$?" -eq "0" ]
then
  echo "[-] downloaded"
else
  echo "[X] download blockhosts FAILED!!"
  exit 1
fi

echo "[-] making blockhosts executable"
chmod +x blockhosts

echo "[-] downloading default config"
cd /usr/local/bin
wget https://raw.githubusercontent.com/palner/blockhosts/refs/heads/main/bhconfig.json &>/dev/null
if [ "$?" -eq "0" ]
then
  echo "[-] downloaded"
else
  echo "[X] download bhconfig.json FAILED!!"
  exit 1
fi

#-- log rotate
echo "[-] set up log rotate"
cat > /etc/logrotate.d/blockhosts << EOF
/var/log/blockhosts.log {
        daily
        copytruncate
        rotate 7
        compress
}
EOF

echo "[-] updating hosts.deny"
if [ "$(grep -Ei 'debian|buntu|mint' /etc/*release)" ]; then
 echo "[-] assuming debian / auth.log system"
 echo "sshd : ALL : spawn (/usr/local/bin/blockhosts) : allow" >> /etc/hosts.deny
 echo "sshd : ALL : allow" >> /etc/hosts.deny
else
 echo "[-] assuming redhat / messages system"
 echo "sshd : ALL : spawn (/usr/local/bin/blockhosts -ssh=/var/log/secure) : allow" >> /etc/hosts.deny
 echo "sshd : ALL : allow" >> /etc/hosts.deny
fi

echo "[+] done."
echo ""
echo "PLEASE, please, update /usr/local/bin/bhconfig.json with your allowed ips."
echo ""
