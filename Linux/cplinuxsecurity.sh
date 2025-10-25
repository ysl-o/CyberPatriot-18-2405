#!/bin/bash
# DO NOT USE - NOT FINISHED AND DEBUGGED

declare -a all_users=()
declare -a all_admins=()

USER=$(whoami)
USERS_ID=$(getent group "users" | cut -d: -f3)

mapfile -t all_users < "$1"
mapfile -t all_admins < "$2"
all_users+=("${all_admins[@]}")

echo "Before you begin, confirm your inputs are correctly formatted."
echo "Both files are text files containing usernames delimited by new lines. Ensure you have no extraneous spaces, newlines, etc."
echo "Your first input should be the path of the text file containing the usernames of all intended nonprivileged users NOT INCLUDING admins."
echo "Your second input should be the path of the text file containing the usernames of all intended admins."
echo ""
echo "The program will now add, delete, and change the passwords of users accordingly."
echo "-------"
output=""
for element in "${all_users[@]}"; do
    output+="${element}, "
done
echo "List of all users, regardless of privilege:"
echo "${output%, }"
echo ""
output=""
for element in "${all_admins[@]}"; do
    output+="${element}, "
done
echo "List of all admins (sudoers):"
echo "${output%, }"
echo "-------"
echo "Confirm for a final time that everything is correct."
echo "[Y/anything else]"
read confirm
if [[ "$confirm" == "Y" || "$confirm" == "y" ]]; then
    echo "Executing commands..."
else
    echo "Aborting program."
    exit
fi

echo ""
echo "Adding nonexistent accounts..."
for USERNAME in "${all_users[@]}"; do
    if ! id "$USERNAME" >/dev/null 2>&1; then
        sudo adduser --disabled-password --gid "$USERS_ID" --gecos "" "$USERNAME"
        echo " - Added user ${USERNAME}"
    fi
done

echo ""
echo "Removing extraneous accounts..."
declare -a reg_users=()
while IFS=: read -r username _ uid _ _ _ _; do
    if (( uid >= 1000 && uid < 65534 )); then
    	reg_users+=("$username")
    fi
done < /etc/passwd

for USERNAME in "${reg_users[@]}"; do
  	if [[ $USERNAME == $USER ]]; then
    	continue
  	fi

  	found=0
  	for authorized in "${all_users[@]}"; do
   		if [[ $authorized == $USERNAME ]]; then
			found=1
    		break
    	fi
	done

	if [ $found -eq 0 ]; then
		sudo deluser --remove-home "$USERNAME"
    	echo "- Deleted user ${USERNAME}"
	fi
done

echo ""
echo "Adding administrator privileges to administrator accounts..."
for USERNAME in "${all_admins[@]}"; do
	if [[ "$USERNAME" != "$USER" ]]; then
    	sudo usermod -aG sudo "$USERNAME"
    	echo " - Gave admin to ${USERNAME}"
	fi
done

echo ""
echo "Removing administrator privileges from extraneous user accounts..."
reg_admins=()
for user in "${reg_users[@]}"; do
    if id -Gn "$user" | grep -qE '\b(sudo|wheel)\b'; then
    	reg_admins+=("$user")
    fi
done
for USERNAME in "${reg_admins[@]}"; do
	if [[ "$USERNAME" == "$USER" ]]; then continue fi
	found=0
	for authorized in "${all_admins[@]}"; do
		if [[ authorized == USERNAME ]]; then found=1 fi
	done
	if (( found == 0 )); then
		sudo deluser -d "$USERNAME" sudo
        echo " - Removed admin from ${USERNAME}"
	fi
done


echo ""
echo "Changing passwords for each account..."
passfile="passwords.txt"
touch "$passfile"
for USERNAME in "${all_users[@]}"; do
    if [[ "$USERNAME" != "$USER" ]]; then
	    declare password=$(tr -dc 'A-Za-z0-9!@#$%^&*()' < /dev/urandom | head -c 12)
	    sudo usermod --password "$password" "$USERNAME"
        echo "User ${USERNAME} has new password \"${password}\""
		printf "%s: %s\n" "${USERNAME}" "${password}" >> "$passfile"
    fi
done

echo ""
echo "----"
echo "Updating packages..."
sudo apt update -y && sudo apt full-upgrade -y && sudo apt-get update -y && sudo apt-get dist-upgrade -y
echo ""
echo "----"
echo ""
echo "Installing SSH, cracklib, unattended upgrade dependencies for modifications..."
sudo apt install openssh-server -y
sudo apt-get install libpam-cracklib -y
sudo apt install unattended-upgrades -y

mapfile -t NECESSARY_PROGRAMS < "$1"
RELEVANT_LINE=0

SYSCTL_CONFIG="/etc/sysctl.conf"
PASS_POLICY_FILE="/etc/login.defs"
SSH_PERM_FILE="/etc/ssh/sshd_config"
PAM_COMMON_PASS="/etc/pam.d/common-password" # Not working
PERIODIC="/etc/apt/apt.conf.d/10periodic" # Not working

# UBUNTU-BASED (EX. MINT) ONLY
AUTO_LOGIN="/etc/lightdm/lightdm.conf" # Not working

alias sed='sed -E'
source ~/.bashrc

ROOT_PASSWORD=$(tr -dc 'A-Za-z0-9!@#$%^&*()' < /dev/urandom | head -c 15)
sudo usermod --password "$ROOT_PASSWORD" root
sudo passwd -l root
echo ""
echo "----"
echo ""
echo "Changed root password to ${ROOT_PASSWORD}"
echo "Disabled logging in to root account"

sudo apt install ufw -y
sudo ufw disable
sudo ufw enable

sudo sed -i -e 's/.*net.ipv4.tcp_syncookies.*/net.ipv4.tcp_syncookies=1/' -e 's/.*net.ipv4.conf.default.rp_filter.*/net.ipv4.conf.default.rp_filter=1/' -e 's/.*net.ipv4.conf.all.rp_filter.*/net.ipv4.conf.all.rp_filter=1/' -e 's/.*net.ipv4.conf.all.secure_redirects.*/net.ipv4.conf.all.secure_redirects=1/' -e 's/.*net.ipv6.conf.all.accept_redirects.*/net.ipv6.conf.all.accept_redirects=0/' -e 's/.*net.ipv4.conf.all.send_redirects.*/net.ipv4.conf.all.send_redirects=0/' -e 's/.*net.ipv4.conf.all.accept_source_route.*/net.ipv4.conf.all.accept_source_route=0/' -e 's/.*net.ipv6.conf.all.accept_source_route.*/net.ipv6.conf.all.accept_source_route=0/' -e 's/.*net.ipv4.conf.all.log_martians.*/net.ipv4.conf.all.log_martians=1/' -e 's/.*kernel.sysrq.*/kernel.sysrq=0/' "$SYSCTL_CONFIG"
echo "Enabled TCP SYN cookie protection to prevent denial of service (DOS)"

echo ""
echo "----"
echo ""
RELEVANT_LINE=$(grep -n "PASS_MAX_DAYS" "$PASS_POLICY_FILE" | awk -F: 'NR==2 {print $1}')
sudo sed -i \
-e "${RELEVANT_LINE}c\\PASS_MAX_DAYS_LINE 30" \
-e "$((RELEVANT_LINE + 1))c\\PASS_MIN_DAYS_LINE 1" \
-e "$((RELEVANT_LINE + 2))c\\PASS_WARN_AGE 10" \
"$PASS_POLICY_FILE"
echo "Modified password time policy"

RELEVANT_LINE=$(grep -n "PermitRootLogin" "$SSH_PERM_FILE" | awk -F: 'NR==1 {print $1}')
sudo sed -i -e "${RELEVANT_LINE}c\\PermitRootLogin no" "$SSH_PERM_FILE"
echo "Removed ability to login to SSH using the root"

sudo nano "$AUTO_LOGIN" # ! DEBUG !
RELEVANT_LINE=$(grep -n "autologin-user=" "$AUTO_LOGIN" | awk -F: 'NR==1 {print $1}')
sudo sed -i \
-e "${RELEVANT_LINE}d" \
-e '$a\allow_guest=false' \
"$AUTO_LOGIN"
echo "Removed automatic login and guest account"
sudo nano "$AUTO_LOGIN" # ! DEBUG !

sudo touch "$PERIODIC"
sudo sed -i -e '$a\APT::Periodic::Update-Package-Lists "1"' "$PERIODIC"
echo "Set automatic package updating"
sudo nano "$PERIODIC" # ! DEBUG !

sed -i \
-e "pam_unix.so/s/$/ remember=10/" \
-e "pam_cracklib.so/s/$/ minlen=14 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/" \
"$PAM_COMMON_PASS"
echo "Set minimum password policies with all security requirements"
sudo nano "$PAM_COMMON_PASS" # ! DEBUG !

echo ""
echo "----"
echo ""
echo "Removing extraneous media files..."
MEDIA_FILES=("jpg" "png" "gif" "webp" "mp4" "mov" "avi" "webm" "mp3" "wav" "aac" "flac" "ogg")
for FILE_EXTENSION in "${MEDIA_FILES[@]}"; do
    IFS=$'\n'
    mapfile -t FOUND_FILES < <(find /home -type f -name "*.${FILE_EXTENSION}")
    unset IFS

    for FILE in "${FOUND_FILES[@]}"; do
        echo " - Removed {$FILE}"
        rm -f "$FILE"
    done
done

echo ""
echo "----"
echo ""
echo "Removing hacking tools and clients..."
HACKS=("dnsrecon" "dnsenum" "proxychains" "tor" "nmap" "slowloris" "zphisher" "nikto" "openvas" "metasploit" "sqlmap" "searchsploit" "hydra" "john" "john-the-ripper" "hashcat" "aircrack-ng" "wifite" "burp" "owasp" "dirb" "gobuster" "empire", "mimikatz" "netcat" "ncat" "lynis" "wireshark")
for HACK in "${HACKS[@]}"; do
    if ! [[ " ${NECESSARY_PROGRAMS[*]} " =~ " ${HACK} " ]]; then
        HACK=$(sudo dpkg --get-selections | grep "$HACK" | head -n 1 | awk '{print $1}')
        while ! [ -z "$HACK" ]; do
            sudo apt-get purge "$HACK" -y
            echo " - Removed suspicious program {$HACK}"
            HACK=$(sudo dpkg --get-selections | grep "$HACK" | head -n 1 | awk '{print $1}')
        done
    fi
done

echo ""
echo "----"
echo ""
echo "Updating systemd..."
sudo apt-get install build-essential devscripts -y
sudo apt-get build-dep systemd -y
mkdir systemd
cd systemd/
wget http://www.freedesktop.org/software/systemd/systemd-220.tar.xz
wget http://archive.ubuntu.com/ubuntu/pool/main/s/systemd/systemd_219-7ubuntu3.dsc
wget http://archive.ubuntu.com/ubuntu/pool/main/s/systemd/systemd_219.orig.tar.xz
wget http://archive.ubuntu.com/ubuntu/pool/main/s/systemd/systemd_219-7ubuntu3.debian.tar.xz
tar xvJf systemd_219.orig.tar.xz 
cd systemd-219/
tar xvJf ../systemd_219-7ubuntu3.debian.tar.xz
uupdate ../systemd-220.tar.xz 220
cd ../systemd-220
dpkg-buildpackage -us -uc
cd ..
sudo dpkg -i *.deb

# Run last; may not work
echo ""
echo "----"
echo ""
echo "Running Clam antivirus..."
sudo apt-get install clamav -y
sudo freshclam
sudo clamscan -i -r --remove=yes /

echo ""
echo "----"
echo ""
echo "It is highly recommended that you reboot at this point."
