#!/usr/bin/env bash

# Description : Opérations post installation pour Debian 10 server (buster).
# Installation et/ou paramétrage de logiciels.
# Usage : sudo ./debian-10-server-post-install.sh
# Licence : GPL-3+
# Auteur : Cédric Goby
# Versioning : https://gitlab.com/CedricGoby/linux-server-install

#-----------------------------------------------------------------------
# Fichiers utilisés par le script
#-----------------------------------------------------------------------
## Définition des variables et des fichiers
. var/source.var
## Définition des fonctions
. func/source.func
#
## Fichiers modèles :
# templates/msmtp.src
# templates/gpg-agent.conf.src
#
## Fichiers de listes :
# conf/gpg-keys-download.list : Clés GPG à installer
# conf/repository-in.list : Dépôts à ajouter
# conf/pkg-in.list : Paquets à installer
# conf/software-download.list : Logiciels à télécharger et installer (hors dépôts)
#
## Journaux
# logs/buster-post-install.log

printf "\n%s\n" "Script de post installation pour Debian 10 server (buster)"

########################################################################
# INITIALISATION & TESTS
########################################################################
#-----------------------------------------------------------------------
# Initialisation du fichier journal
#-----------------------------------------------------------------------
> "$_file_logs"

#-----------------------------------------------------------------------
# Vérification de l'exécution du script avec les droits d'administration
#-----------------------------------------------------------------------
if [[ $(id -u) != 0 ]]; then
	printf "\n%s\n%s\n\n" "[ ERREUR ] --> Vous devez lancer le script avec sudo ou être root." "Usage : sudo ./debian-10-server-post-install.sh"
	exit 0
fi

#-----------------------------------------------------------------------
# Tests de compatibilité du script
#-----------------------------------------------------------------------
# Test de compatibilité du script avec l'OS cible (Ubuntu 18.04 bionic)
if [[ "$_os_current" != "$_os_target" ]]; then
	printf "\n%s\n%s\n" "[ ERREUR ] --> Le script de post-installation n'est pas compatible avec votre système." "Le script de post-installation est uniquement compatible avec "$_os_target". Arrêt du script !"
	exit 0
else
	printf "\n%s\n" "Le script est compatible avec "$_os_target"... [ OK ]"
fi

########################################################################
# MISES A JOUR DU SYSTÈME
########################################################################
printf "\n%s\n" "MISES A JOUR DU SYTÈME"

# Test la présence du processus dpkg avec pidof
# Il ne peut pas y avoir deux processus de mise à jour simultanés.
if [[ ! -z $(pidof dpkg) ]]; then
    printf "\n%s\n%s\n\n" "[ ERREUR ] --> Le processus dpkg (gestionnaire de paquets) est en cours d'utilisation." ". Arrêt du script !"
    exit 0
fi

# Récupération de la liste des mises à jour
_cmd="apt-get update >/dev/null 2>>"$_file_logs""
_cmd_text="Récupération de la liste des mises à jour..."
f_cmd "$_cmd" "$_cmd_text"

# Mise à jour du système
_cmd="apt-get -y upgrade >/dev/null 2>>"$_file_logs""
_cmd_text="Mise à jour du système..."
f_cmd "$_cmd" "$_cmd_text"

# Installation des logiciels pour l'installation de paquets
_cmd="apt-get -y install software-properties-common \
	dirmngr \
	apt-transport-https \
	lsb-release \
	ca-certificates \
	curl \
	gpg-agent >/dev/null 2>>"$_file_logs""
_cmd_text="Installation des logiciels pour l'installation de paquets..."
f_cmd "$_cmd" "$_cmd_text"
########################################################################
# SÉCURITÉ
########################################################################

#-----------------------------------------------------------------------
# Paramétrage openSSH
#-----------------------------------------------------------------------
printf "\n%s\n" "PARAMÉTRAGE OPENSSH"

#-----------------------------------------------------------------------
# Copier une clé publique
#-----------------------------------------------------------------------
printf "\n%s" "Souhaitez-vous copier une clé publique pour un utilisateur ? (yYoO / nN)"

read choice
	case $choice in
		[yYoO]*) read -p "Utilisateur : " _user
			read -p "Clé publique : " _public_key
			# Si le dossier .ssh et le fichier .ssh/authorized_keys n'existent pas ils sont créés
			if [ ! -d "$_dir_ssh" ]; then
				# Chemin si l'utilisateur n'est pas root
				if [[ $(id -u) != 0 ]]; then
					_home="/home"
				fi				
				_cmd='mkdir "$_home/$_user/$_dir_ssh" && touch "$_home/$_user/$_dir_ssh/$_file_authorized_keys"'
				_cmd_text="Création du fichier "$_home/$_user/$_dir_ssh/$_file_authorized_keys"..."
				f_cmd "$_cmd" "$_cmd_text"
				_cmd='chmod 700 "$_home/$_user/$_dir_ssh" && chmod 600 "$_home/$_user/$_dir_ssh/$_file_authorized_keys"'
				_cmd_text="Application des droits sur "$_home/$_user/$_dir_ssh/$_file_authorized_keys"..."
				f_cmd "$_cmd" "$_cmd_text"								
			fi
			# Copie de la clé publique dans le fichier ~/.ssh/authorized_keys
			_cmd='echo -e "$_public_key" >> $_home/$_user/$_dir_ssh/$_file_authorized_keys'
			_cmd_text="Copie de la clé publique dans le fichier "$_home/$_user/$_dir_ssh/$_file_authorized_keys"..."
			f_cmd "$_cmd" "$_cmd_text"
			
			#-----------------------------------------------------------------------
			# Interdire l'authentification par mot de passe
			#-----------------------------------------------------------------------
			printf "\n%s" "Souhaitez-vous interdire l'authentification SSH par mot de passe ? (yYoO / nN)"
			
			read choice
				case $choice in
							# On remplace la ligne suivant celle qui contient "UsePAM yes" dans le fichier /etc/ssh/sshd_config
				  [yYoO]*) _cmd="sed -i '/UsePAM yes/!b;n;cPasswordAuthentication no' $_file_sshd_config"
						_cmd_text="Désactivation de l'authentification SSH par mot de passe..."
						f_cmd "$_cmd" "$_cmd_text";;
				  [nN]*) printf "%s\n" "Suite du programme...";;
				  *) printf "%s\n" "Erreur de saisie. Suite du programme...";;
				esac
			
			# Redémarrage du service SSH
			_cmd="systemctl restart sshd >/dev/null 2>>"$_file_logs""
			_cmd_text="Redémarrage du service SSH..."
			f_cmd "$_cmd" "$_cmd_text";;			
			
		[nN]*) printf "%s\n" "Aucune clé à copier. Suite du programme...";;
		*) printf "%s\n" "Erreur de saisie. Suite du programme...";;
	esac

########################################################################
# INSTALLATION DES PAQUETS
########################################################################
printf "\n%s\n" "INSTALLATION DES PAQUETS"

#-----------------------------------------------------------------------
# Installation de clés GPG
#-----------------------------------------------------------------------

# Installation des clés GPG listées dans le fichier gpg-keys-download.list
while IFS=$'\t' read _name _url _fingerprint; do
	# Si le nom du paquet ne commence pas par # dans le fichier gpg-keys-download.list on le traite
	if [[ $_name != \#* ]] ; then
		# Vérification de la disponibilité de la clé au téléchargement
		curl --output /dev/null --silent --head --fail "$_url"
		if [[ "$?" = 0 ]]; then
			# Téléchargement et installation de la clé
			_cmd="curl -fsSL $_url | apt-key add -"
			_cmd_text="Téléchargement et installation de la clé pour $_name..."
			f_cmd "$_cmd" "$_cmd_text"
			# Vérification de l'empreinte de la clé
			_cmd_text="Vérification de l'empreinte de la clé pour $_name..."
			printf "\n%s\n" "$_cmd_text Veuillez patienter."
			_cmd=$(apt-key adv --list-public-keys --with-fingerprint --with-colons)
			if [[ "$_cmd" =~ "$_fingerprint" ]]; then
				printf "%s\n" "$_cmd_text [ OK ]"
				else
				# Echec de la vérification de l'empreinte de la clé
				printf "%s\n" "La vérification de l'empreinte de la clé a échoué pour $_name, arrêt de la procédure d'installation de $_name... [ AVERTISSEMENT ]"
			fi			
		else
			# Clé non disponible au téléchargement
			printf "\n%s\n" "Le fichier distant $_name n'existe pas ou est temporairement indisponible, arrêt de la procédure d'installation de $_name... [ AVERTISSEMENT ]"
		fi
	fi
done <"$_src_gpg_keys_download"

#-----------------------------------------------------------------------
# Installation de dépôts
#-----------------------------------------------------------------------
printf "\n%s\n" "Installation des dépôts"

# Installation des dépôts listés dans le fichier repository-in.list
while IFS=$'\t' read _name _repository _type; do
	# Si le nom du dépôt ne commence pas par # dans le fichier repository-in.list on le traite
	if [[ "$_name" != \#* ]] ; then
		if [[ "$_type" = ppa ]] ; then
		_cmd="add-apt-repository -y "$_repository" >/dev/null 2>>"$_file_logs""
		else
		_cmd="echo -e '"$_repository"' | tee /etc/apt/sources.list.d/"$_name".list"
		fi
	_cmd_text="Installation du dépôt "$_repository"..."
	f_cmd "$_cmd" "$_cmd_text"
	fi
done < "$_src_pkg_repository"

# Récupération de la liste des mises à jour
_cmd="apt-get update >/dev/null 2>>"$_file_logs""
_cmd_text="Récupération de la liste des mises à jour..."
f_cmd "$_cmd" "$_cmd_text"

#----------------------------------------------------------------------------------------------------
# Téléchargement et installation de logiciels (hors dépôts)
#----------------------------------------------------------------------------------------------------
printf "\n%s\n" "Téléchargement et installation de logiciels hors dépôts"

# Installation de gdebi-core
# gdebi-core permet d'installer des paquets au format .deb en ligne de commande
# en résolvant les dépendances.
# Si gdebi-core n'est pas installé, on l'installe.
_package="gdebi-core"
f_install_package "$_package"

# Installation des logiciels listés dans le fichier software-download.list
while IFS=$'\t' read _name _url _typesum _checksum _type; do
	# Si le nom du paquet ne commence pas par # dans le fichier software-download.list on le traite
	if [[ $_name != \#* ]] ; then
		# Vérification de la disponibilité du fichier au téléchargement
		curl --output /dev/null --silent --head --fail "$_url"
		if [[ "$?" = 0 ]]; then
			# Téléchargement du fichier
			_cmd="curl -L $_url -o $_name"
			_cmd_text="Téléchargement de $_name..."
			f_cmd "$_cmd" "$_cmd_text"
			# Vérification de la somme de contrôle
			_cmd_text="Vérification de la somme de contrôle pour $_name..."
			printf "\n%s\n" "$_cmd_text Veuillez patienter."
			_cmd=$($_typesum $_name | awk {'print $1'};)
			echo "\n$_cmd\n"
			if [[ "$_cmd" = "$_checksum" ]]; then
				printf "%s\n" "$_cmd_text [ OK ]"
				# Installation du logiciel
				# Copie du fichier binaire et attribution des droits
				if [[ $_type = "binary" ]] ; then
				_cmd="mv $_name /usr/local/bin/ && chmod +x /usr/local/bin/$_name"
				_cmd_text="Installation du fichier binaire $_name..."
				f_cmd "$_cmd" "$_cmd_text"
				else
				# Installation du fichier deb avec gdebi
				_cmd="gdebi --n $_name"
				_cmd_text="Installation du fichier deb $_name..."
				f_cmd "$_cmd" "$_cmd_text"				
				fi
			else
				# Echec de la vérification de la somme de contrôle, le logiciel ne sera pas installé
				printf "%s\n" "La vérification de la somme de contrôle a échoué pour $_name, arrêt de la procédure d'installation de $_name... [ AVERTISSEMENT ]"
			fi			
		else
			# Paquet non disponible au téléchargement
			printf "\n%s\n" "Le fichier distant $_name n'existe pas ou est temporairement indisponible, arrêt de la procédure d'installation de $_name... [ AVERTISSEMENT ]"
		fi
	fi
done <"$_src_software_download"

#-----------------------------------------------------------------------
# Installation de paquets via les dépôts
#-----------------------------------------------------------------------
printf "\n%s\n" "Installation de paquets via les dépôts"

# Installation des paquets listés dans le fichier pkg-in.list via les dépôts
while IFS=$'\t' read _package; do
	# Si le nom du paquet ne commence pas par # dans le fichier pkg-in.list on le traite
	if [[ $_package != \#* ]] ; then
	  f_install_package "$_package"
	fi
done <"$_src_pkg_in"

########################################################################
# CONFIGURATION DES PAQUETS
########################################################################
printf "\n%s\n" "CONFIGURATION DES PAQUETS"

#-----------------------------------------------------------------------
# Configuration firewall avec ufw
#-----------------------------------------------------------------------

# Configuration de ufw
_package="ufw"
# Si le paquet est installé
if f_check_for_package "$_package"; then
	# Interdiction des connexions entrantes
	_cmd="ufw default deny incoming"
	_cmd_text="Interdiction des connexions entrantes..."
	f_cmd "$_cmd" "$_cmd_text"
	# Autorisation des connexions sortantes
	_cmd="ufw default allow outgoing"
	_cmd_text="Autorisation des connexions sortantes..."
	f_cmd "$_cmd" "$_cmd_text"
	# Ouverture des ports tcp 22,80,443
	_cmd="ufw allow 22,80,443/tcp"
	_cmd_text="Ouverture des ports tcp 22,80,443..."
	f_cmd "$_cmd" "$_cmd_text"
	# Lancement de ufw au démarrage du système
	_cmd="ufw enable"
	_cmd_text="Lancement de "$_package" au démarrage du système..."
	f_cmd "$_cmd" "$_cmd_text"
fi

#-----------------------------------------------------------------------
# Configuration msmtp
#-----------------------------------------------------------------------
# Configuration de msmtp
_package="msmtp"
# Si le paquet est installé
if f_check_for_package "$_package"; then

# Création de la paire de clés
	# Définition du nom et du mot de passe pour la clé
	printf "\n%s\n" "Création d'une paire de clé GPG"
	read -p "Email (sera également utilisé comme Real Name) : " _email_from
	f_submit_password	
	# Options pour la création de la paire de clés
	cat >key_options <<EOF
     %echo Generating an OpenPGP key
     Key-Type: RSA
     Key-Length: 3072
     Subkey-Type: RSA
     Subkey-Length: 3072
     Name-Real: $_email_from
     Name-Comment: No comment
     Name-Email: $_email_from
     Expire-Date: 0
     Passphrase: $_password
     # Do a commit here, so that we can later print "done" :-)
     %commit
     %echo done
EOF
	# Génération de la paire de clés
	_cmd="gpg --batch --generate-key key_options"
	_cmd_text="Génération de la paire de clés"
	f_cmd "$_cmd" "$_cmd_text"

	# Si le fichier gpg-agent.conf n'existe pas on le crée
	if [ ! -f "$_file_gpg_conf" ]; then
		# Chemin si l'utilisateur n'est pas root
		if [[ $(id -u) != 0 ]]; then
			_gpg_conf_dir="~/.gnupg"
			else
			_gpg_conf_dir="/root/.gnupg"
		fi
		_cmd='cp "$_src_config_gpg" "$_gpg_conf_dir/$_file_config_gpg"'
		_cmd_text="Copie du fichier de configuration pour gpg..."
		f_cmd "$_cmd" "$_cmd_text"
		_cmd='chmod 700 "$_gpg_conf_dir" && chmod 600 "$_gpg_conf_dir/$_file_config_gpg"'
		_cmd_text="Application des droits sur "$_gpg_conf_dir/$_file_config_gpg"..."
		f_cmd "$_cmd" "$_cmd_text"		
	fi

# Configuration ssmtp
	# Copie du fichier de configuration pour msmtp
	_cmd="cp "$_src_msmtp" "$_file_config_msmtp""
	_cmd_text="Copie du fichier de configuration pour msmtp..."
	f_cmd "$_cmd" "$_cmd_text"
	printf "\n%s\n" "Configuration de $_package"
	# Variables de configuration ssmtp
	read -p "Serveur SMTP : " _host
	read -p "Port SMTP : " _port
	read -p "Authentification (on - off) : " _authentication
	read -p "TLS (on - off) : " _tls
	read -p "TLS cert check (on - off) : " _tls_cert_check
	read -p "Adresse email (from) : " _email_from
	read -p "Utilisateur SMTP : " _login

	# Soumission du mot de passe du compte email
	printf "\n%s\n" "Mot de passe pour le compte SMTP"
	f_submit_password
	
	# Chiffrement du fichier de mot de passe pour msmtp
	printf "\n%s\n" "Chiffrement du fichier de mot de passe pour msmtp"
	echo "$_password" > /etc/.msmtp-password
	_cmd="gpg --encrypt /etc/.msmtp-password -r "$_login""
	_cmd_text="Chiffrement du fichier de mot de passe pour msmtp"
	f_cmd "$_cmd" "$_cmd_text"
	rm /etc/.msmtp-password
	
	# Insertion d'antislash devant les caractères ayant une signification pour sed
	_password="$(<<< "$_password" sed -e 's`[][\\/.*^$]`\\&`g')"
	_file_passwd_msmtp="$(<<< "$_file_passwd_msmtp" sed -e 's`[][\\/.*^$]`\\&`g')"

	# Modification du fichier /etc/msmtprc
	_cmd="sed -i -e 's/^host/host "$_host"/' \
	-e 's/^port$/port "$_port"/' \
	-e 's/^auth$/auth "$_authentication"/' \
	-e 's/^tls$/tls "$_tls"/' \
	-e 's/^tls_certcheck$/tls_certcheck "$_tls_cert_check"/' \
	-e 's/^from$/from "$_email_from"/' \
	-e 's/^user$/user "$_login"/' \
	-e 's/^password$/passwordeval gpg --no-tty -q -d "$_file_passwd_msmtp"/' "$_file_config_msmtp""
	_cmd_text="Modification du fichier "$_file_config_msmtp"..."
	f_cmd "$_cmd" "$_cmd_text"
	
	# Test du MTA
	printf "\n%s\n" "Test du MTA"
	_cmd="ls -la /usr/sbin/sendmail 2>/dev/null | grep -q "$_package""
	_cmd_text="Test du MTA"
	f_cmd "$_cmd" "$_cmd_text"	
fi

#-----------------------------------------------------------------------
# Configuration fail2ban
#-----------------------------------------------------------------------
# Configuration de fail2ban
_package="fail2ban"
# Si le paquet est installé
if f_check_for_package "$_package"; then
	# Création du fichier de configuration
	_cmd="cp "$_src_config_fail2ban" "$_file_config_fail2ban""
	_cmd_text="Création du fichier de configuration fail2ban "$_file_config_fail2ban"..."
	f_cmd "$_cmd" "$_cmd_text"
	
	# Activation de la prison SSH (SSH est installé par défaut sur l'OS)
	_cmd="sed -i '/^\[sshd\]/a enabled = true' "$_file_config_fail2ban""
	_cmd_text="Activation de la prison SSH fail2ban..."
	f_cmd "$_cmd" "$_cmd_text"
	
	# Redémarrage du service
	_cmd="systemctl restart fail2ban"
	_cmd_text="Redémarrage du service fail2ban..."
	f_cmd "$_cmd" "$_cmd_text"
fi

#-----------------------------------------------------------------------
# Configuration logwatch
#-----------------------------------------------------------------------
# Configuration de logwatch
_package="logwatch"
# Si le paquet est installé
if f_check_for_package "$_package"; then
	printf "\n%s\n" "Configuration de $_package"
	# Prompt utilisateur
	read -p "Destinataire : " _mailto
	read -p "Expéditeur : " _mailfrom

	# Modification du fichier /usr/share/logwatch/default.conf/logwatch.conf
	_cmd="sed -i -e 's/MailTo = root/MailTo = "$_mailto"/' \
	-e 's/MailFrom = Logwatch/MailFrom = "$_mailfrom"/' "$_file_config_logwatch""
	_cmd_text="Modification du fichier "$_file_config_logwatch"..."
	f_cmd "$_cmd" "$_cmd_text"
fi

########################################################################
# SYSTÈME
########################################################################
printf "\n%s\n" "TÂCHES PLANIFIÉES"

#-----------------------------------------------------------------------
# Création des tâches planifiées
#-----------------------------------------------------------------------

# Sauvegarde du fichier /etc/crontab vers /etc/crontab.bak
_cmd="cp $_file_crontab $_file_crontab.bak"
_cmd_text="Sauvegarde du fichier $_file_crontab vers $_file_crontab.bak"
f_cmd "$_cmd" "$_cmd_text"

# Planification des mises à jour avec /etc/crontab
_crontab_job="15 01   * * 0   root    /usr/bin/apt-get update && /usr/bin/apt-get -y upgrade && /usr/bin/apt-get -y autoremove >/dev/null"
_cmd='echo -e "$_crontab_job" >> $_file_crontab'
_cmd_text="Planification de la mise à jour du système..."
f_cmd "$_cmd" "$_cmd_text"

########################################################################
# RAPPORT
########################################################################
# Envoi du fichier de logs 
printf "\n%s" "Souhaitez-vous envoyer le rapport d'installation par email ? (yYoO / nN)"

read choice
	case $choice in
		[yYoO]*)
			# Mot de passe de la clé GPG
			printf "\n%s\n" "Mot de passe de la clé GPG"
			_cmd="gpg -d "$_file_passwd_msmtp""
			_cmd_text="Mot de passe de la clé GPG"
			f_cmd "$_cmd" "$_cmd_text"
			# Envoi du fichier de logs par email
			printf "\n%s\n" "Envoi du fichier de logs par email"			
			read -p "Destinataire des logs : " _mailto
			read -p "Expéditeur des logs : " _mailfrom									
			msmtp -d -a default -t <<EOF
From: $_mailfrom
To: $_mailto
Content-Type: text/plain; charset=UTF-8
Subject: $(hostname) $(hostname -I) - Logs post installation
$(cat "$_file_logs")
EOF
			_cmd_text="Envoi du fichier de logs à "$_mailto""
			f_cmd "$_cmd" "$_cmd_text";;
		[nN]*) printf "%s\n" "Aucun mot de passe pour la clé. Suite du programme...";;
		*) printf "%s\n" "Erreur de saisie. Suite du programme...";;
	esac

########################################################################
# FIN DE PROGRAMME
########################################################################
printf "\n%s\n%s\n" "Fin du programme de post installation!" "Vous pouvez consulter le fichier journal "$_file_logs""
exit 0
