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
# LOGICIELS PRÉ-REQUIS
########################################################################
# Installation des logiciels pré-requis
_cmd="apt-get -y install software-properties-common \
	dirmngr \
	apt-transport-https \
	lsb-release \
	ca-certificates \
	curl \
	gnupg >/dev/null 2>>"$_file_logs""
_cmd_text="Installation des logiciels pré-requis..."
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
printf "\n%s" "Souhaitez-vous copier une clé publique SSH ? (yYoO / nN)"

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
						
			#-----------------------------------------------------------------------
			# Interdire l'authentification par mot de passe
			#-----------------------------------------------------------------------
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
	_cmd_text="Installation du dépôt "$_name"..."
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

# Création de la paire de clés pour chiffrer le fichier de mot de passe
	# Définition du nom et du mot de passe pour la clé
	printf "\n%s\n" "Création d'une paire de clé GPG"
	read -p "Email (sera également utilisé comme Real Name) : " _email_gpg_key
	f_submit_password	
	# Options pour la création de la paire de clés
	cat >key_options <<EOF
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
     # Do a commit here, so that we can later print "done" :-)
     %commit
     %echo done
EOF
	# Génération de la paire de clés (lance également l'agent GPG gpg-agent)
	_cmd="gpg --batch --generate-key key_options"
	_cmd_text="Génération d'une paire de clés pour chiffrer les mots de passe..."
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

	# On arrête l'agent GPG. Ainsi, la configuration (gpg-agent.conf)
	# sera chargée à la prochaine invocation de gpg-agent
	_cmd="gpgconf --kill gpg-agent"
	_cmd_text="Arrêt de l'agent GPG..."
	f_cmd "$_cmd" "$_cmd_text"
		
	# Démarrage de l'agent GPG à l'ouverture de session
	cat << 'EOF' >> $HOME/.bashrc
eval $(gpg-agent --daemon)
GPG_TTY=$(tty)
export GPG_TTY=$(tty)
EOF

# Configuration ssmtp
	# Copie du fichier de configuration global pour msmtp
	_cmd="cp "$_src_msmtp" "$_file_config_msmtp""
	_cmd_text="Copie du fichier de configuration globale pour "$_package" (SMTP)..."
	f_cmd "$_cmd" "$_cmd_text"
	printf "\n%s\n" "Configuration de "$_package""
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
	# GPG needs to know who is going to be opening the file and who sent it. Since this file is for you,
	# there's no need to specify a sender, and you are the recipient.
	printf "\n%s\n" "Chiffrement du fichier de mot de passe SMTP"
	_cmd="gpg -e -r "$_login" /etc/.msmtp-password"
	_cmd_text="Chiffrement du fichier de mot de passe SMTP..."
	f_cmd "$_cmd" "$_cmd_text"
	
	# Suppression du fichier temporaire contenant le mot de passe SMTP
	_cmd="rm /etc/.msmtp-password"
	_cmd_text="Suppression du fichier temporaire contenant le mot de passe SMTP..."
	f_cmd "$_cmd" "$_cmd_text"

	# Déchiffrement du fichier de mot de passe (enregistre le mot de passe de la clé avec l'agent GPG)
	_cmd="gpg --quiet --decrypt "$_file_passwd_msmtp" >/dev/null 2>>"$_file_logs""
	#_cmd="echo | gpg -s >/dev/null 2>>"$_file_logs""
	_cmd_text="Déchiffrement du fichier de mot de passe (enregistre le mot de passe de la clé avec l'agent GPG)..."
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
	
	# Test du MTA
	printf "\n%s\n" "Test du MTA"
	_cmd="ls -la /usr/sbin/sendmail 2>/dev/null | grep -q "$_package""
	_cmd_text="Test du MTA $_package..."
	f_cmd "$_cmd" "$_cmd_text"	
fi

########################################################################
# INSTALLATION D'APACHE (reverse proxy)
########################################################################

printf "\n%s" "Souhaitez-vous installer apache (reverse proxy SSL) ? (yYoO / nN)"

read choice
	case $choice in
		[yYoO]*) 
			_package="apache2"
			f_install_package "$_package"

			# Activation de modules
			_cmd="a2enmod ssl xml2enc proxy >/dev/null 2>>"$_file_logs""
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
# CRÉATION DU CERTIFICAT SSL
########################################################################

printf "\n%s" "Souhaitez-vous créer un certificat SSL (Wildcard) ? (yYoO / nN)"

read choice
	case $choice in
		[yYoO]*) 
			# certbot est installé si il n'est pas présent
			_package="certbot"
			f_install_package "$_package"

			# Arrêt d'apache si il tourne
			_service="apache2"
			if systemctl is-active --quiet "$_service" ; then
				# Arrêt d'apache
				_status="1"
				_cmd="systemctl stop "$_service" >/dev/null 2>>"$_file_logs""
				_cmd_text="Arrêt de "$_service"..."
				f_cmd "$_cmd" "$_cmd_text"
			fi

			# Création du certificat SSL (Wildcard)
			printf "\n%s\n" "Création du certificat SSL Let's Encrypt (Wildcard)"
			read -p "Domaine du certificat SSL : " _domain
			read -p "Email attaché au certificat SSL : " _email_letsencrypt
			_cmd="certbot certonly --dry-run --standalone --non-interactive --agree-tos -m "$_email_letsencrypt" -d "*.$_domain" -d "$_domain" >> "$_file_logs""
			_cmd_text="Création du certificat SSL Let's Encrypt (Wildcard) pour "$_domain"..."
			f_cmd "$_cmd" "$_cmd_text"			
			# Redémarrage d'apache si il tournait
			if [[ $_status = 1 ]] ; then
				# Démarrage d'apache
				_cmd="systemctl start "$_service" >/dev/null 2>>"$_file_logs""
				_cmd_text="Démarrage de "$_service"..."
				f_cmd "$_cmd" "$_cmd_text"
			fi;;			
		[nN]*) printf "%s\n" "Pas de certificat à installer. Suite du programme...";;
		*) printf "%s\n" "Erreur de saisie. Suite du programme...";;
	esac

#-----------------------------------------------------------------------
# Configuration fail2ban
#-----------------------------------------------------------------------
# Configuration de fail2ban
_package="fail2ban"
# Si le paquet est installé
if f_check_for_package "$_package"; then
	# Création du fichier de configuration
	_cmd="cp "$_src_config_fail2ban" "$_file_config_fail2ban""
	_cmd_text="Création du fichier de configuration "$_package" "$_file_config_fail2ban"..."
	f_cmd "$_cmd" "$_cmd_text"
	
	# Activation de la prison SSH
	_cmd="sed -i '/^\[sshd\]/a enabled = true' "$_file_config_fail2ban""
	_cmd_text="Activation de la prison "$_package"..."
	f_cmd "$_cmd" "$_cmd_text"
	
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
	
	# Rechargement de la configuration fail2ban
	_cmd="fail2ban-client reload >/dev/null 2>>"$_file_logs""
	_cmd_text="Rechargement de la configuration "$_package"..."
	f_cmd "$_cmd" "$_cmd_text"

	# Liste des prisons actives
	_cmd="fail2ban-client status >>"$_file_logs""
	_cmd_text="Liste des prisons actives pour "$_package"..."

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
			# Envoi du fichier de logs par email
			printf "\n%s\n" "Envoi du fichier de logs par email"			
			read -p "Destinataire des logs : " _mailto
			read -p "Expéditeur des logs : " _mailfrom	
								
			msmtp -d -a default -t >/dev/null 2>>"$_file_logs" <<EOF
From: $_mailfrom
To: $_mailto
Content-Type: text/plain; charset=UTF-8
Subject: $(hostname) $(hostname -I) - Logs post installation
$(cat "$_file_logs")
EOF
			_cmd_text="Envoi du fichier de logs à "$_mailto"..."
			f_cmd "$_cmd" "$_cmd_text";;
		[nN]*) printf "%s\n" "Aucun mot de passe pour la clé. Suite du programme...";;
		*) printf "%s\n" "Erreur de saisie. Suite du programme...";;
	esac

########################################################################
# FIN DE PROGRAMME
########################################################################
printf "\n%s\n%s\n" "Fin du programme de post installation!" "Vous pouvez consulter le fichier journal "$_file_logs""
exit 0
