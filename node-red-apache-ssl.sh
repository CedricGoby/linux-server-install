#!/usr/bin/env bash

# Description : Installation de node-red, apache et certbot (Let's encrypt) sous Ubuntu 16.04 LTS.
# Configuration de node-red sur un sous-domaine avec proxy Apache et SSL, lancement de node-red au démarrage par un utilisateur non-root.
# Usage : ./node-red-apache-ssl.sh sous-domaine domaine.tld utilisateur email
# Licence : GPL-3+
# Auteur : Cédric Goby
# Versioning : https://github.com/CedricGoby/linux-server-install
# Ressources : https://nodered.org/ - https://httpd.apache.org/ - https://certbot.eff.org/docs/

# Fichier de configuration de node-red (utilisateur qui lance node-red)
_node-red-config-file="/home/$3/.node-red/settings.js"

# Mise à jour du système
sudo apt-get install && sudo apt-get upgrade -y
# Installation de nodejs LTS
curl -sL https://deb.nodesource.com/setup_8.x | sudo -E bash - 
sudo apt-get install -y nodejs
# Installation de build tools pour la compilation et installation via npm
sudo apt-get install -y build-essential
# Installation de node-red
sudo npm install -g --unsafe-perm node-red
# Installation de modules pour node-red
sudo npm install -g --unsafe-perm node-red-admin
# Exécuter node-red au démarrage 
sudo cat >node-red.service <<EOL
[Unit]
Description=Node-RED
After=syslog.target network.target

[Service]
ExecStart=/usr/bin/node-red
Restart=on-failure
KillSignal=SIGINT

# log output to syslog as 'node-red'
SyslogIdentifier=node-red
StandardOutput=syslog

# non-root user to run as
WorkingDirectory=/home/$3/
User=$3
Group=$3

[Install]
WantedBy=multi-user.target
EOL
sudo chown root:root node-red.service
sudo mv node-red.service /etc/systemd/system/
sudo systemctl enable node-red
# Modification de la configuration de node-red : autoriser uniquement les connexions sur l'interface locale (127.0.0.1)
sed -i 's#//uiHost#uiHost#' "$_node-red-config-file"
# Démarrage manuel de node-red
sudo systemctl start node-red
# Installation d'Apache
sudo apt-get install -y apache2
# Activation de modules pour Apache
sudo a2enmod xml2enc headers ssl proxy proxy_balancer proxy_http proxy_wstunnel
# Activation SSL
sudo a2ensite default-ssl
# Création du vhost pour le sous-domaine
sudo cat >$1.$2.conf <<EOL
<VirtualHost *:80>
        ServerName $1.$2
</VirtualHost>
EOL
sudo chown root:root $1.$2.conf && sudo chmod 644 $1.$2.conf
sudo mv $1.$2.conf /etc/apache2/sites-available/
sudo a2ensite $1.$2
# Redémarrage d'Apache
sudo systemctl restart apache2
# Installation de certbot
sudo add-apt-repository -y ppa:certbot/certbot
sudo apt-get update
sudo apt-get install -y python-certbot-apache
# Génération des certificats Let's Encrypt
sudo certbot --agree-tos --no-eff-email -m $4 -d $2,$1.$2 --apache certonly
# Modification du vhost pour le sous-domaine (configuration SSL)
sudo cat >$1.$2.conf <<EOL
<VirtualHost *:80>
        ServerName $1.$2
        Redirect permanent / https://$1.$2/
</VirtualHost>

<IfModule mod_ssl.c>
        <VirtualHost *:443>
                ServerName $1.$2
                
                SSLCertificateFile /etc/letsencrypt/live/$2/fullchain.pem
                SSLCertificateKeyFile /etc/letsencrypt/live/$2/privkey.pem
                
                SSLEngine on
                SSLProtocol all -SSLv2 -SSLv3
                SSLHonorCipherOrder on
                SSLCompression off
                SSLOptions +FakeBasicAuth +ExportCertData +StrictRequire
                SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256
                Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"

                ProxyPreserveHost On
                ProxyPass               /comms        ws://localhost:1880/comms
                ProxyPassReverse        /comms        ws://localhost:1880/comms
                ProxyPass               /             http://127.0.0.1:1880/
                ProxyPassReverse        /             http://127.0.0.1:1880/
        </VirtualHost>
</IfModule>
EOL
sudo chown root:root $1.$2.conf && sudo chmod 644 $1.$2.conf
sudo mv $1.$2.conf /etc/apache2/sites-available/
sudo systemctl restart apache2
