#!/bin/bash
OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
RESET='\e[0m'


function print_ascii_art {
cat << "EOF"
   
 __          __  _     _    _            _        
 \ \        / / | |   | |  | |          | |       
  \ \  /\  / /__| |__ | |__| | __ _  ___| | _____ 
   \ \/  \/ / _ \ '_ \|  __  |/ _` |/ __| |/ / __|
    \  /\  /  __/ |_) | |  | | (_| | (__|   <\__ \
     \/  \/ \___|_.__/|_|  |_|\__,_|\___|_|\_\___/
                                                  

					daniel.torres@owasp.org
					https://github.com/DanielTorres1

EOF
}


print_ascii_art

echo -e "$OKBLUE [+] Instalando WEB hacks $RESET" 
cd webhacks
go build
cd ..
go build web-buster.go
go build webData.go

cp webData /usr/bin/
cp web-buster /usr/bin/

mkdir /usr/share/webhacks 2>/dev/null
cp -R wordlist /usr/share/webhacks

chmod a+x /usr/bin/webData
chmod a+x /usr/bin/web-buster


echo -e " [+] INSTALACION COMPLETA"
