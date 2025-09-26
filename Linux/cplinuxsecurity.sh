mapfile -t NECESSARY_PROGRAMS < "$1"
RELEVANT_LINE=0

SYSCTL_CONFIG=/etc/sysctl.conf
PASS_POLICY_FILE=/etc/login.defs
SSH_PERM_FILE=/etc/ssh/sshd_config
PAM_COMMON_PASS=/etc/apt/apt.conf.d/10periodic

# UBUNTU ONLY
AUTO_LOGIN=/etc/lightdm/lightdm.conf

ROOT_PASSWORD=$(tr -dc 'A-Za-z0-9!@#$%^&*()' < /dev/urandom | head -c 15)
sudo sh -c 'echo root:${ROOT_PASSWORD} | chpasswd'
sudo passwd -l root
echo "Changed root password to ${ROOT_PASSWORD}"
echo "Disabled logging in to root account"
echo ""

sudo apt update && sudo apt full-upgrade && sudo apt install ufw
sudo apt-get dist-upgrade
sudo ufw disable
sudo ufw enable

sed -i 's,net.ipv4.tcp_syncookies = 0,net.ipv4.tcp_syncookies = 1,g' "$SYSCTL_CONFIG"
echo "Enabled TCP SYN cookie protection to prevent denial of service (DOS)"
echo ""

grep -n -m 1 "PASS_MAX_DAYS" "$PASS_POLICY_FILE" | awk -F: '{$RELEVANT_LINE=$1}'
sed -i '${RELEVANT_LINE}c,PASS_MAX_DAYS_LINE\t30' "$PASS_POLICY_FILE"
sed -i '$((RELEVANT_LINE + 1))c,PASS_MIN_DAYS_LINE\t1' "$PASS_POLICY_FILE"
sed -i '$((RELEVANT_LINE + 2))c,PASS_WARN_AGE\t10' "$PASS_POLICY_FILE"
echo "Modified password time policy"
echo ""

grep -n -m 1 "PermitRootLogin" "$SSH_PERM_FILE" | awk -F: '{$RELEVANT_LINE=$1}'
sed -i '${RELEVANT_LINE}c,PermitRootLogin no' "$SSH_PERM_FILE"
echo "Removed ability to login to SSH using the root"
echo ""

grep -n -m 1 "autologin-user" "$AUTO_LOGIN" | awk -f: '{$RELEVANT_LINE=$1}'
sed -i '${RELEVANT_LINE}d' "$AUTO_LOGIN"
echo "Removed having an automatic login user; not the user itself"
echo ""

grep -n -m 1 "allow_guest" "$AUTO_LOGIN" | awk -f: '{$RELEVANT_LINE=$1}'
sed -i '${RELEVANT_LINE}c,allow_guest=false' "$AUTO_LOGIN"
echo "Does not allow a guest account to the computer"
echo ""

sed -i '1c,APT::Periodic::Update-Package-Lists' | awk -f: "$PERIODIC"
echo "Set automatic package updating"
echo ""

grep -n -m 1 "pam_unix.so" "$PAM_COMMON_PASS" | awk -f: '{$RELEVANT_LINE=$1}'
sed -i '${RELEVANT_LINE}s,$, remember=5' "$PAM_COMMON_PASS"
echo "Set to remember last 10 user passwords"
echo ""

grep -n -m 1 "pam_cracklib.so" "$PAM_COMMON_PASS" | awk -f: '{$RELEVANT_LINE=$1}'
sed -i '${RELEVANT_LINE}s,$, minlen=14 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1' "$PAM_COMMON_PASS"
echo "Set minimum password policies with all security requirements"
echo ""

echo "----"
echo "Removing extraneous media files..."
MEDIA_FILES=("jpg" "png" "gif" "webp" "mp4" "mov" "avi" "webm" "mp3" "wav" "aac" "flac" "ogg")
for FILE_EXTENSION in "${MEDIA_FILES[@]}"; do
    IFS=$'\n'
    mapfile -t FOUND_FILES < <(find /home -type f -name "*.${FILE_EXTENSION}")
    unset IFS

    for FILE in "${FOUND_FILES[@]}"; do
        rm -f "$FILE"
    done

    echo " - Removed {$FILE}"
done

echo "----"
echo "Removing hacking tools and clients..."
HACKS=("dnsrecon" "dnsenum" "proxychains" "tor" "nmap" "slowloris" "zphisher" "nikto" "openvas" "metasploit" "sqlmap" "searchsploit" "hydra" "john" "john-the-ripper" "hashcat" "aircrack-ng" "wifite" "burp" "owasp" "dirb" "gobuster" "empire", "mimikatz" "netcat" "ncat" "lynis" "wireshark")
for HACK in "${HACKS[@]}"; do
    if ! [[ " ${NECESSARY_PROGRAMS[*]} " =~ " ${HACK} " ]]; then
        HACK=$(sudo dpkg --get-selections | grep "$HACK" | head -n 1 | awk '{print $1}')
        while ! [ -z "$HACK" ]; then
            sudo apt-get purge "$HACK"
            echo " - Removed suspicious program {$HACK}"
            HACK=$(sudo dpkg --get-selections | grep "$HACK" | head -n 1 | awk '{print $1}')
        done
    fi
done

echo "----"
echo "Updating systemd..."
sudo apt-get install build-essential devscripts
sudo apt-get build-dep systemd
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
echo "----"

# Run last; may not work
echo "Running Clam antivirus..."
sudo apt-get update
apt-get install clamav
freshclam
clamscan -i -r --remove=yes /

sudo reboot