# linux-server-install
Scripts d'installation pour serveurs Linux.<br />
Installation scripts for Linux servers.

## node-red-apache-ssl.sh
Installation de node-red, apache et certbot (Let's encrypt) pour Ubuntu 16.04 LTS.<br />
Génération d'un certificat SSL avec certbot.<br />
Configuration de node-red sur un sous-domaine avec proxy Apache et SSL.<br />
Installation d'un script de démarrage automatique de node-red avec un utilisateur non-root.

Node-red, apache and certbot (Let's encrypt) install for Ubuntu 16.04 LTS.<br />
SSL certificate generation with certbot.<br />
Node-red configuration for a sub-domain with Apache proxy and SSL.<br />
Startup script for node-red with a non-root user.

### Prérequis / prerequisite
Une installation fraîche d'Ubuntu 16.04 LTS.<br />
Un domaine et un sous-domaine pointant vers le serveur.<br />
Un utilsateur avec les droits sudo (cet utilisateur lance le script).

Ubuntu 16.04 fresh install.<br />
A domain and a sud-domain pointing to the server.
A user with sudo rights (this user launch this script).

## apache-vhosts
Vhosts SSL Apache pour différentes applications serveur
