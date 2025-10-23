#!/bin/bash

if command -v x-ui &> /dev/null; then
    echo "Обнаружена установленная панель x-ui."
    echo "Удаление x-ui..."
    # Тихое удаление x-ui (если установлен через официальный скрипт)
    /usr/local/x-ui/x-ui uninstall -y &>/dev/null || true
    rm -rf /usr/local/x-ui /etc/x-ui /usr/bin/x-ui /etc/systemd/system/x-ui.service
    systemctl daemon-reexec
    systemctl daemon-reload
    rm /root/3x-ui.txt
    echo "x-ui успешно удалена. Продолжаем выполнение скрипта..."
fi


echo "Installing 3x-ui..."
cd /usr/local/ || exit 1
#tag_version=$(curl -Ls "https://api.github.com/repos/MHSanaei/3x-ui/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
wget -q -O x-ui-linux-${ARCH}.tar.gz https://github.com/MHSanaei/3x-ui/releases/download/v2.6.7/x-ui-linux-amd64.tar.gz

systemctl stop x-ui 2>/dev/null
rm -rf /usr/local/x-ui/
tar -xzf x-ui-linux-${ARCH}.tar.gz
rm -f x-ui-linux-${ARCH}.tar.gz

cd x-ui || exit 1
chmod +x x-ui
[[ "$ARCH" == armv* ]] && mv bin/xray-linux-${ARCH} bin/xray-linux-arm && chmod +x bin/xray-linux-arm
chmod +x x-ui bin/xray-linux-${ARCH}
cp -f x-ui.service /etc/systemd/system/
wget -q -O /usr/bin/x-ui https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.sh
chmod +x /usr/local/x-ui/x-ui.sh /usr/bin/x-ui
echo -e "\3x-ui started successfully!"

echo "Changing credentials..."
PASSWORD=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 12 ; echo '')
WEBPATH=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 12 ; echo '')
/usr/local/x-ui/x-ui setting -username "admin" -password "${PASSWORD}" -webBasePath "${WEBPATH}" -port "8080"

SERVER_IP=$(hostname -I | awk '{print $1}')
OUTPUT_FILE="3x-ui.txt"

systemctl restart x-ui

echo -e "\nПанель 3x-ui доступна по ссылке: http://$SERVER_IP:8080/$WEBPATH" | tee -a $OUTPUT_FILE
echo -e "Логин: admin" | tee -a $OUTPUT_FILE
echo -e "Пароль: $PASSWORD" | tee -a $OUTPUT_FILE

export url="http://$SERVER_IP:8080/$WEBPATH"
export username="admin"
export password="${PASSWORD}"