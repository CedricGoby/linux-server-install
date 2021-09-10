# Linux server install
Scripts d'installation pour des serveurs Linux.

## Structure des dossiers
  * func : fonctions utilisées dans les scripts
  * log : journaux d'exécution des scripts
  * softwares : Dépôts, clés publiques, logiciels à installer...
  * templates : fichiers modèles
  * var : variables utilisées dans les scripts

## Scripts

### debian-10-server-post-installation.sh
Ce script interactif permet de sélectionner, d'installer et de configurer différents logiciels après l'installation initiale de Debian : ufw, fail2ban, logwatch, apticron, msmtp, certbot, apache2, docker-ce...  
