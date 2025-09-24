#!/bin/bash

declare -a all_users=()
declare -a all_admins=()

mapfile -t all_users < "$1"
mapfile -t all_admins < "$2"
if ! printf '%s\n' "${all_admins[@]}" | grep -qFx -- "root"; then
    all_admins+=("root")
fi
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
if [[ "$confirm" == "Y" ]]; then
    echo "Executing commands..."
else
    exit
fi

echo ""
echo "Adding nonexistent accounts..."
for USERNAME in "${all_users[@]}"; do
    if ! id "$USERNAME" >/dev/null 2>&1; then
        sudo adduser -y --disabled-password --gecos "" "$USERNAME"
        echo " - Added user ${USERNAME}"
    fi
done

echo ""
echo "Removing extraneous accounts..."
declare -a reg_users=()
while IFS=: read -r username _ uid _ _ _ _; do
    if (( uid >= 1000 )); then
    	reg_users+=("$username")
    fi
done < /etc/passwd

for USERNAME in "${reg_users[@]}"; do
    if [[ ! " ${all_users[*]} " =~ [[:space:]]${USERNAME}[[:space:]] ]]; then
        sudo deluser --remove-home "$USERNAME"
        echo " - Deleted user ${USERNAME}"
    fi
done

echo ""
echo "Adding administrator privileges to administrator accounts..."
for USERNAME in "${all_admins[@]}"; do
    sudo usermod -aG sudo "$USERNAME"
    echo " - Gave admin to ${USERNAME}"
done

echo ""
echo "Removing administrator privileges from extraneous user accounts..."
reg_admins=()
for user in $reg_users; do
    if id -Gn "$user" | grep -qE '\b(sudo|wheel)\b'; then
    	reg_admins+=("$user")
    fi
done
for USERNAME in "${reg_admins[@]}"; do
    if [[ ! " ${admins[*]} " =~ [[:space:]]${USERNAME}[[:space:]] ]]; then
        sudo deluser -d "$USERNAME" sudo
        echo " - Removed admin from ${USERNAME}"
    fi
done

echo ""
echo "Changing passwords for each account..."
for USERNAME in "${users[@]}"; do
    declare password=$(tr -dc 'A-Za-z0-9!?%=' < /dev/urandom | head -c 12)
    sudo usermod --password "$password" "$USERNAME"
    echo "User ${USERNAME} has new password \"${password}\""
done

echo ""
echo "All done!"
