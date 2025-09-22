#!/bin/bash

sudo

declare -a all_users=()
declare -a all_admins=()

all_users=$(cat "$1" | xargs echo | tr ' ' '\n' | sed -e 's/\(.*\)/"\1"/' | tr '\n' ',')
all_users="[$(echo ${all_users::-1})]"

all_admins=$(cat "$2" | xargs echo | tr ' ' '\n' | sed -e 's/\(.*\)/"\1"/' | tr '\n' ',')
all_admins="[$(echo ${all_admins::-1})]"

echo "Before you begin, confirm your inputs are correctly formatted."
echo "Both files are text files containing usernames delimited by new lines. Ensure you have no extraneous spaces, newlines, etc."
echo "Your first input should be the path of the text file containing the usernames of all intended nonprivileged users NOT INCLUDING admins."
echo "Your second input should be the path of the text file containing the usernames of all intended admins."
echo ""
echo "The program will now add, delete, and change the passwords of users accordingly."
echo "Confirm for a final time that everything is correct. [Y/anything else]"
read confirm
if [["$confirm" == "Y"]]; then
    echo "Executing commands..."
else
    exit
fi

echo ""
echo "Adding nonexistent accounts..."
for USERNAME in "${all_users[@]}"; do
    if ! id "$USERNAME" >/dev/null 2>&1; then
        sudo adduser "$USERNAME"
        echo " - Added user ${USERNAME}"
    fi
done

echo ""
echo "Removing extraneous accounts..."
IFS=$'\n' read -r -d '' -a users < <(getent passwd | cut -d: -f1)
for USERNAME in "${users[@]}"; do
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
IFS=$'\n' read -r -d '' -a admins < <(getent group sudo | cut -d: -f4)
for USERNAME in "${admins[@]}"; do
    if [[ ! " ${admins[*]} " =~ [[:space:]]${USERNAME}[[:space:]] ]]; then
        sudo deluser -d "$USERNAME" sudo
        echo " - Removed admin from ${USERNAME}"
    fi
done

echo ""
echo "Changing passwords for each account..."
for USERNAME in "${users[@]}"; do
    declare password=$(tr -dc 'A-Za-z0-9!?%=' < /dev/urandom | head -c 12)
    usermod --password "$password" "$USERNAME"
    echo "User ${USERNAME} has new password \"${password}\""
done

echo ""
echo "All done!"
