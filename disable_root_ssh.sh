#!/bin/sh

USERNAME=user
PASSWORD=asiga73E4laoK

useradd -m -G sudo -s /bin/bash "${USERNAME}"
echo "${USERNAME}:${PASSWORD}" | chpasswd

sed -e "s/PermitRootLogin yes/PermitRootLogin no/g" -i /etc/ssh/sshd_config
sed -e "s/#PermitRootLogin yes/PermitRootLogin no/g" -i /etc/ssh/sshd_config
sed -e "s/#PermitRootLogin no/PermitRootLogin no/g" -i /etc/ssh/sshd_config

systemctl restart sshd
