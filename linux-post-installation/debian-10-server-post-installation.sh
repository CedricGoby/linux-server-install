#!/usr/bin/env bash

# Description : Opérations post installation pour Debian 10 server (buster).
# Installation et/ou paramétrage de logiciels.
# Usage : 
# git clone https://gitlab.com/CedricGoby/linux-server-install
# cd linux-server-install
# ./debian-10-server-post-install.sh
# Licence : GPL-3+
# Auteur : Cédric Goby
# Versioning : https://gitlab.com/CedricGoby/linux-server-install

########################################################################
# FICHIERS UTILISÉS PAR LE SCRIPT
########################################################################
## Définition des variables et des fichiers
. var/source.var
## Définition des fonctions
. func/source.func
#
## Fichiers modèles :
# templates/msmtp.src
# templates/gpg-agent.conf.src
# templates/bash_aliases.src
#
## Fichiers de listes :
# conf/gpg-keys-download.list : Clés GPG à installer
# conf/repository-in.list : Dépôts à ajouter
# conf/pkg-in.list : Paquets à installer
# conf/software-download.list : Logiciels à télécharger et installer (hors dépôts)
#
## Journaux
_file_logs="log/$(lsb_release -cs)-post-install.log"

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
# Test de compatibilité du script avec l'OS cible
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

########################################################################
# MISE EN PLACE DU FICHIER BASH ALIASES
########################################################################
# Vérification de l'absence du fichier ~/.bash_aliases
if [ ! -f ~/.bash_aliases ]; then
	# Copie du fichier modèle ~/.bash_aliases
	_cmd="cp "$_src_bash_aliases" "$_file_bash_aliases""
	_cmd_text="Copie du fichier de bash aliases..."
	f_cmd "$_cmd" "$_cmd_text"

	# Modification du fichier ~/.bashrc
	cmd=$(cat >> ~/.bashrc << EOF
if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi
EOF
)
	_cmd_text="Modification du fichier bashrc..."
	f_cmd "$_cmd" "$_cmd_text"

fi

########################################################################
# INSTALLATION DE LOGICIELS PRÉ-REQUIS
########################################################################
printf "\n%s\n" "INSTALLATION DE LOGICIELS PRÉ-REQUIS"
_cmd="apt-get -y install software-properties-common \
	dirmngr \
	apt-transport-https \
	lsb-release \
	ca-certificates \
	acl \
	curl \
	gnupg >/dev/null 2>>"$_file_logs""
_cmd_text="Installation des logiciels pré-requis..."
f_cmd "$_cmd" "$_cmd_text"

########################################################################
# COPIE D'UNE CLÉ PUBLIQUE POUR L'ACCÈS SSH
########################################################################
printf "\n%s\n" "COPIE D'UNE CLÉ PUBLIQUE POUR L'ACCÈS SSH"

printf "\n%s" "Souhaitez-vous copier une clé publique pour l'accès SSH ? (yYoO / nN)"

read choice
	case $choice in
		[yYoO]*) read -p "Utilisateur machine distante : " _user
			read -p "Clé publique SSH : " _public_key
			# Si le répertoire .ssh et le fichier .ssh/authorized_keys n'existent pas ils sont créés
			if [ ! -d "$_dir_ssh" ]; then
				# Chemin si l'utilisateur n'est pas root
				if [[ $_user != root ]]; then
					_home="/home"
				fi
				# Création du répertoire .ssh				
				_cmd="mkdir "$_home/$_user/$_dir_ssh""
				_cmd_text="Création du dossier "$_home/$_user/$_dir_ssh"..."
				f_cmd "$_cmd" "$_cmd_text"
				# Création du fichier .ssh/authorized_keys
				_cmd="touch "$_home/$_user/$_dir_ssh/$_file_authorized_keys""
				_cmd_text="Création du fichier "$_home/$_user/$_dir_ssh/$_file_authorized_keys"..."
				f_cmd "$_cmd" "$_cmd_text"						
			fi
			
			# Ajout de la clé publique dans le fichier ~/.ssh/authorized_keys
			_cmd="echo -e "$_public_key" >> $_home/$_user/$_dir_ssh/$_file_authorized_keys"
			_cmd_text="Ajout de la clé publique dans le fichier "$_home/$_user/$_dir_ssh/$_file_authorized_keys"..."
			f_cmd "$_cmd" "$_cmd_text"

			# Aplication des propriétés et des droits
			_cmd="chown -R "$_user" "$_home/$_user/$_dir_ssh""
			_cmd_text="Propriété du répertoire "$_home/$_user/$_dir_ssh"..."
			f_cmd "$_cmd" "$_cmd_text"
			
			_cmd="chmod 700 "$_home/$_user/$_dir_ssh""
			_cmd_text="Application des droits sur "$_home/$_user/$_dir_ssh"..."
			f_cmd "$_cmd" "$_cmd_text"			
			
			_cmd="chmod 600 "$_home/$_user/$_dir_ssh/$_file_authorized_keys""
			_cmd_text="Application des droits sur "$_home/$_user/$_dir_ssh/$_file_authorized_keys"..."
			f_cmd "$_cmd" "$_cmd_text"
						
########################################################################
# INTERDICTION DE L'ACCÈS SSH PAR MOT DE PASSE
########################################################################
			printf "\n%s" "Souhaitez-vous interdire l'authentification SSH par mot de passe ? (yYoO / nN)"
			
			read choice
				case $choice in
							# On remplace "#PasswordAuthentication yes" par "PasswordAuthentication no" dans le fichier /etc/ssh/sshd_config
				  [yYoO]*) _cmd="sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' $_file_sshd_config"
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
# TÉLÉCHARGEMENT ET INSTALLATION DE CLÉS PUBLIQUES
########################################################################
printf "\n%s\n" "TÉLÉCHARGEMENT ET INSTALLATION DE CLÉS PUBLIQUES"

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

########################################################################
# AJOUTS DE DÉPÔTS DANS LA LISTE 
########################################################################
printf "\n%s\n" "AJOUTS DE DÉPÔTS DANS LA LISTE"

# Installation des dépôts listés dans le fichier repository-in.list
while IFS=$'\t' read _name _repository _type; do
	# Si le nom du dépôt ne commence pas par # dans le fichier repository-in.list on le traite
	if [[ "$_name" != \#* ]] ; then
		if [[ "$_type" = ppa ]] ; then
		_cmd="add-apt-repository -y "$_repository" >/dev/null 2>>"$_file_logs""
		else
		_cmd="echo -e '"$_repository"' | tee /etc/apt/sources.list.d/"$_name".list"
		fi
	_cmd_text="Installation du dépôt "$_name"..."
	f_cmd "$_cmd" "$_cmd_text"
	fi
done < "$_src_pkg_repository"

# Récupération de la liste des mises à jour
_cmd="apt-get update >/dev/null 2>>"$_file_logs""
_cmd_text="Récupération de la liste des mises à jour..."
f_cmd "$_cmd" "$_cmd_text"

########################################################################
# TÉLÉCHARGEMENT ET INSTALLATION DE LOGICIELS HORS DEPÔTS
########################################################################
printf "\n%s\n" "TÉLÉCHARGEMENT ET INSTALLATION DE LOGICIELS HORS DEPÔTS"

########################################################################
# INSTALLATION DE GDEBI
########################################################################
# gdebi-core permet d'installer des paquets au format .deb en ligne de commande

# Si gdebi-core n'est pas installé, on l'installe.
_package="gdebi-core"
f_install_package "$_package"

########################################################################
# INSTALLATION DES LOGICIELS HORS DEPÔTS
########################################################################
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
				# Installation du paquet deb avec gdebi
				_cmd="gdebi --n $_name"
				_cmd_text="Installation du paquet deb $_name..."
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

########################################################################
# INSTALLATION DE PAQUETS AVEC LES DEPÔTS
########################################################################
printf "\n%s\n" "INSTALLATION DE PAQUETS AVEC LES DEPÔTS"

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
printf "\n%s\n" "CONFIGURATION DES PAQUETS INSTALLÉS"

########################################################################
# CONFIGURATION UFW
########################################################################
_package="ufw"
# Si le paquet est installé
if f_check_for_package "$_package"; then
	printf "\n%s\n" "CONFIGURATION DE "$_package""
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

########################################################################
# GPG, MSMTP, ALIASES
########################################################################
_package="msmtp"
# Si le paquet est installé
if f_check_for_package "$_package"; then
	printf "\n%s\n" "CONFIGURATION DE "$_package""

########################################################################
# CRÉATION D'UNE PAIRE DE CLÉS GPG
########################################################################
	# Création des dossiers et fichiers pour gnupg
	_cmd="gpg --list-keys"
	_cmd_text="Création des dossiers et fichiers pour gnupg..."
	f_cmd "$_cmd" "$_cmd_text"

	# Si le fichier gpg-agent.conf n'existe pas on le crée
	if [ ! -f "$_file_gpg_conf" ]; then
		# Chemin si l'utilisateur n'est pas root
		if [[ $(id -u) != 0 ]]; then
			_gpg_conf_dir="~/.gnupg"
			else
			_gpg_conf_dir="/root/.gnupg"
		fi
		_cmd="cp "$_src_config_gpg" "$_gpg_conf_dir"/"$_file_config_gpg""
		_cmd_text="Copie du fichier de configuration pour gpg..."
		f_cmd "$_cmd" "$_cmd_text"
		_cmd="chmod 700 "$_gpg_conf_dir" && chmod 600 "$_gpg_conf_dir"/"$_file_config_gpg""
		_cmd_text="Application des droits sur "$_gpg_conf_dir"/"$_file_config_gpg"..."
		f_cmd "$_cmd" "$_cmd_text"		
	fi

# Création de la paire de clés pour chiffrer le fichier de mot de passe
	# Définition du nom et du mot de passe pour la clé
	printf "\n%s\n" "CRÉATION D'UNE PAIRE DE CLÉS GPG"
	read -p "Email (sera également utilisé comme Real Name) : " _email_gpg_key
	f_submit_password
	
	# Création du fichier key_options pour la génération de la paire de clés
	cmd=$(cat >key_options <<	EOF
     %echo Generating an OpenPGP key
     Key-Type: RSA
     Key-Length: 3072
     Subkey-Type: RSA
     Subkey-Length: 3072
     Name-Real: $_email_gpg_key
     Name-Comment: No comment
     Name-Email: $_email_gpg_key
     Expire-Date: 0
     Passphrase: $_password
     # Do a commit here, so that we can later print "done"
     %commit
     %echo done
EOF
)
	_cmd_text="Création du fichier key_options..."
	f_cmd "$_cmd" "$_cmd_text"

	# Génération de la paire de clés (lance également l'agent GPG)
	_cmd="gpg --batch --generate-key key_options"
	_cmd_text="Génération d'une paire de clés pour chiffrer les mots de passe..."
	f_cmd "$_cmd" "$_cmd_text"

	# Suppression du fichier d'options pour la création de la paire de clés 
	_cmd="rm key_options"
	_cmd_text="Suppression du fichier d'options pour la création de la paire de clés..."
	f_cmd "$_cmd" "$_cmd_text"

	# Rechargement de la configuration de l'agent GPG
	_cmd="gpgconf --kill gpg-agent"
	_cmd_text="Arrêt de gpg-agent"
	f_cmd "$_cmd" "$_cmd_text"
	sleep 5
	_cmd="gpg-connect-agent /bye"
	_cmd_text="Démarrage de gpg-agent"
	f_cmd "$_cmd" "$_cmd_text"
	sleep 5

	# Enregistrement du mot de passe de la clé avec gpg-preset-passphrase
	_keygrip_gpg_key=$(gpg --list-secret-keys --with-keygrip | sed -n '8 p' | awk -F'= ' '{print $2}')
	_cmd="/usr/lib/gnupg2/gpg-preset-passphrase -c "$_keygrip_gpg_key" <<< '$_password'"
	_cmd_text="Enregistrement de la clé avec gpg-agent"
	f_cmd "$_cmd" "$_cmd_text"

########################################################################
# CONFIGURATION MSMTP
########################################################################
	printf "\n%s\n" "CONFIGURATION DE "$_package""
	# Copie du fichier de configuration global pour msmtp
	_cmd="cp "$_src_msmtp" "$_file_config_msmtp""
	_cmd_text="Copie du fichier de configuration globale pour "$_package" (SMTP)..."
	f_cmd "$_cmd" "$_cmd_text"
	printf "\n%s\n" "Paramètres de configuration pour "$_package""
	# Variables de configuration ssmtp
	read -p "Serveur SMTP : " _host
	read -p "Port SMTP : " _port
	read -p "Authentification (on - off) : " _authentication
	read -p "TLS (on - off) : " _tls
	read -p "TLS cert check (on - off) : " _tls_cert_check
	read -p "Adresse email (from) : " _email_from
	read -p "login SMTP : " _login

	# Soumission du mot de passe SMTP
	printf "\n%s\n" "Mot de passe pour le compte SMTP "$_login""
	f_submit_password
	
	# Copie du mot de passe SMTP dans un fichier temporaire
	printf "\n%s\n" "Copie du mot de passe SMTP dans un fichier temporaire"
	_cmd="echo "$_password" > /etc/.msmtp-password"
	_cmd_text="Copie du mot de passe SMTP dans un fichier temporaire..."
	f_cmd "$_cmd" "$_cmd_text"
	
	# Chiffrement du fichier de mot de passe SMTP
	# GPG doit savoir qui va ouvrir le fichier et qui l'envoi. Puisque le fichier est pour vous,
	# il est inutile de spécifier un expéditeur, et vous êtes le destinataire.
	printf "\n%s\n" "Chiffrement du fichier de mot de passe SMTP"
	_cmd="gpg -e -r "$_login" /etc/.msmtp-password"
	_cmd_text="Chiffrement du fichier de mot de passe SMTP..."
	f_cmd "$_cmd" "$_cmd_text"
	
	# Suppression du fichier temporaire contenant le mot de passe SMTP
	_cmd="rm /etc/.msmtp-password"
	_cmd_text="Suppression du fichier temporaire contenant le mot de passe SMTP..."
	f_cmd "$_cmd" "$_cmd_text"
		
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
	
	# Mise en place des logs
	f_log_setup "$_package"

	# Modification du fichier /etc/aliases
	_cmd="echo "root: $_email_from" >> /etc/aliases"
	_cmd_text="Modification du fichier /etc/aliases..."
	f_cmd "$_cmd" "$_cmd_text"
	
	# Test du MTA
	printf "\n%s\n" "Test du MTA"
	_cmd="ls -la /usr/sbin/sendmail 2>/dev/null | grep -q "$_package""
	_cmd_text="Test du MTA $_package..."
	f_cmd "$_cmd" "$_cmd_text"

fi

########################################################################
# INSTALLATION D'APACHE (reverse proxy)
########################################################################
printf "\n%s" "Souhaitez-vous installer apache ? (yYoO / nN)"

read choice
	case $choice in
		[yYoO]*)
			_package="apache2"
			f_install_package "$_package"

			printf "\n%s\n" "CONFIGURATION DE "$_package""
			# Activation de modules
			_cmd="a2enmod ssl xml2enc proxy rewrite headers proxy_http proxy_wstunnel >/dev/null 2>>"$_file_logs""
			_cmd_text="Activation de modules "$_package"..."
			f_cmd "$_cmd" "$_cmd_text"

			# Redémarrage d'apache
			_cmd="systemctl restart "$_package" >/dev/null 2>>"$_file_logs""
			_cmd_text="Redémarrage de "$_package"..."
			f_cmd "$_cmd" "$_cmd_text";;			
		[nN]*) printf "%s\n" ""$_package" ne sera pas installé. Suite du programme...";;
		*) printf "%s\n" "Erreur de saisie. Suite du programme...";;
	esac

########################################################################
# CRÉATION DU CERTIFICAT SSL LET'S ENCCRYPT
########################################################################
printf "\n%s" "Souhaitez-vous créer un certificat SSL (Wildcard) ? (yYoO / nN)"

read choice
	case $choice in
		[yYoO]*) 
			# certbot est installé si il n'est pas présent
			_package="certbot"
			f_install_package "$_package"

			printf "\n%s\n" "CONFIGURATION DE "$_package""
			# Arrêt d'apache si il fonctionne
			_service="apache2"
			if systemctl is-active --quiet "$_service" ; then
				# Arrêt d'apache
				_status="1"
				_cmd="systemctl stop "$_service" >/dev/null 2>>"$_file_logs""
				_cmd_text="Arrêt de "$_service"..."
				f_cmd "$_cmd" "$_cmd_text"
			fi

			# Création du certificat SSL (Wildcard)
			printf "\n%s\n" "Création du certificat SSL Let's Encrypt"
			read -p "Domaine du certificat SSL : " _domain
			read -p "Email attaché au certificat SSL : " _email_letsencrypt
			_cmd="certbot certonly --standalone --non-interactive --agree-tos -m "$_email_letsencrypt" -d "$_domain" >> "$_file_logs""
			_cmd_text="Création du certificat SSL Let's Encrypt pour "$_domain"..."
			f_cmd "$_cmd" "$_cmd_text"			

			# Redémarrage d'apache si il fonctionnait avant la création du certificat
			if [[ $_status = 1 ]] ; then
				# Démarrage d'apache
				_cmd="systemctl start "$_service" >/dev/null 2>>"$_file_logs""
				_cmd_text="Démarrage de "$_service"..."
				f_cmd "$_cmd" "$_cmd_text"
			fi;;			
		[nN]*) printf "%s\n" "Pas de certificat à installer. Suite du programme...";;
		*) printf "%s\n" "Erreur de saisie. Suite du programme...";;
	esac

########################################################################
# CONFIGURATION FAIL2BAN
########################################################################
_package="fail2ban"
# Si le paquet est installé
if f_check_for_package "$_package"; then
	printf "\n%s\n" "CONFIGURATION DE "$_package""
	# Création du fichier de configuration
	_cmd="cp "$_src_config_fail2ban" "$_file_config_fail2ban""
	_cmd_text="Création du fichier de configuration "$_package" "$_file_config_fail2ban"..."
	f_cmd "$_cmd" "$_cmd_text"
	
	# Activation de la prison SSH
	_jail="ssh"
	_cmd="sed -i '/^\[sshd\]/a enabled = true' "$_file_config_fail2ban""
	_cmd_text="Activation de la prison "$_jail"..."
	f_cmd "$_cmd" "$_cmd_text"
	
	# Activation de la prison APACHE
	_jail="apache2"
	if f_check_for_package "$_jail"; then
		_cmd="sed -i -e '/^\[apache-auth\]/a enabled = true' \
		-e '/^\[apache-badbots\]/a enabled = true' \
		-e '/^\[apache-noscript\]/a enabled = true' \
		-e '/^\[apache-overflows\]/a enabled = true' \
		-e '/^\[apache-nohome\]/a enabled = true' \
		-e '/^\[apache-botsearch\]/a enabled = true' \
		-e '/^\[apache-fakegooglebot\]/a enabled = true' \
		-e '/^\[apache-modsecurity\]/a enabled = true' \
		-e '/^\[apache-shellshock\]/a enabled = true' "$_file_config_fail2ban""
		_cmd_text="Activation de la prison "$_jail"..."
		f_cmd "$_cmd" "$_cmd_text"
	fi

	# Configuration de fail2ban avec ufw si ufw est activé
    if grep ENABLED=yes /etc/ufw/ufw.conf>/dev/null; then
		_cmd="sed -i -e 's/banaction = iptables-multiport/banaction = ufw/' -e 's/banaction_allports = iptables-allports/banaction_allports = ufw/' $_file_config_fail2ban"
		_cmd_text="Configuration de fail2ban avec ufw..."
		f_cmd "$_cmd" "$_cmd_text"		
	fi
	
	# Rechargement de la configuration fail2ban
	_cmd="fail2ban-client reload >/dev/null 2>>"$_file_logs""
	_cmd_text="Rechargement de la configuration "$_package"..."
	f_cmd "$_cmd" "$_cmd_text"

	# Liste des prisons actives
	_cmd="fail2ban-client status | cut -c4- >>"$_file_logs""
	_cmd_text="Liste des prisons actives pour "$_package"..."
	f_cmd "$_cmd" "$_cmd_text"
fi

########################################################################
# CONFIGURATION LOGWATCH
########################################################################
_package="logwatch"
# Si le paquet est installé
if f_check_for_package "$_package"; then
	printf "\n%s\n" "CONFIGURATION DE "$_package""
	# Prompt utilisateur
	read -p "Destinataire logwatch : " _mailto
	read -p "Expéditeur logwatch : " _mailfrom

	# Modification du fichier /usr/share/logwatch/default.conf/logwatch.conf
	_cmd="sed -i -e 's/MailTo = root/MailTo = "$_mailto"/' \
	-e 's/MailFrom = Logwatch/MailFrom = "$_mailfrom"/' \
	-e 's/Output = stdout/Output = mail/' "$_file_config_logwatch""
	_cmd_text="Modification du fichier "$_file_config_logwatch"..."
	f_cmd "$_cmd" "$_cmd_text"
	
	# Envoi du mail logwatch
	_cmd="logwatch --detail 5"
	_cmd_text="Envoi du mail logwatch..."
	f_cmd "$_cmd" "$_cmd_text"
fi

########################################################################
# CONFIGURATION APTICRON
########################################################################
_package="apticron"
# Si le paquet est installé
if f_check_for_package "$_package"; then
	printf "\n%s\n" "CONFIGURATION DE "$_package""
	# Prompt utilisateur
	read -p "Destinataire apticron : " _mailto
	read -p "Expéditeur apticron : " _mailfrom

	if [ ! -f "$_file_config_apticron" ]; then
	# Copie du fichier de configuration
	_cmd="cp "$_src_config_apticron" "$_file_config_apticron""
	_cmd_text="Copie du fichier de configuration $_file_config_apticron..."
	f_cmd "$_cmd" "$_cmd_text"
	# Modification du fichier
	_cmd="sed -i -e 's/EMAIL="root"/EMAIL=\"$_mailto\"/' -e 's/# CUSTOM_FROM=""/CUSTOM_FROM=\"$_mailfrom\"/' "$_file_config_apticron""
	_cmd_text="Ajout du destinataire et de l'expéditeur dans le fichier $_file_config_apticron..."
	f_cmd "$_cmd" "$_cmd_text"
	fi

	# Envoi du mail apticron
	_cmd="apticron"
	_cmd_text="Envoi du mail apticron..."
	f_cmd "$_cmd" "$_cmd_text"
fi

########################################################################
# MISE EN PLACE DES TÂCHES PLANIFIÉES
########################################################################
printf "\n%s\n" "MISE EN PLACE DES TÂCHES PLANIFIÉES"

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
# ENVOI DES LOGS PAR EMAIL
########################################################################
printf "\n%s" "Souhaitez-vous envoyer le rapport d'installation par email ? (yYoO / nN)"

read choice
	case $choice in
		[yYoO]*)
			# Envoi du fichier de logs par email
			printf "\n%s\n" "Envoi du fichier de logs par email"			
			read -p "Destinataire des logs : " _mailto
			read -p "Expéditeur des logs : " _mailfrom	
								
			_cmd="msmtp -d -a default -t >/dev/null 2>>"$_file_logs" <<EOF
From: $_mailfrom
To: $_mailto
Content-Type: text/plain; charset=UTF-8
Subject: $(hostname) $(hostname -I) - Logs post installation
$(cat "$_file_logs")
EOF"
			_cmd_text="Envoi du fichier de logs à "$_mailto"..."
			f_cmd "$_cmd" "$_cmd_text";;
		[nN]*) printf "%s\n" "Les logs ne seront pas envoyés. Suite du programme...";;
		*) printf "%s\n" "Erreur de saisie. Suite du programme...";;
	esac

########################################################################
# FIN DE PROGRAMME
########################################################################
printf "\n%s\n%s\n" "FIN DU PROGRAMME DE POST INSTALLATION!" "Vous pouvez consulter le fichier journal "$_file_logs""
exit 0
