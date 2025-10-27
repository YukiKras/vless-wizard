#!/bin/bash

OUTPUT_FILE="/root/3x-ui.txt"

check_and_free_port() {
    local PORT=$1
    echo "Проверка порта $PORT..."
    PID=$(lsof -ti tcp:$PORT)

    if [ -n "$PID" ]; then
        echo "Порт $PORT занят процессом PID $PID."

        if docker ps --format '{{.Names}} {{.Ports}}' | grep -q ":$PORT"; then
            CONTAINER=$(docker ps --format '{{.Names}} {{.Ports}}' | grep ":$PORT" | awk '{print $1}')
            echo "Порт $PORT используется Docker-контейнером: $CONTAINER"
            echo "Останавливаю контейнер и отключаю автозапуск..."
            docker stop "$CONTAINER" >/dev/null 2>&1
            docker update --restart=no "$CONTAINER" >/dev/null 2>&1
        else
            echo "Порт $PORT используется обычным процессом. Завершаю его..."
            kill -9 "$PID" >/dev/null 2>&1 || true
        fi
    else
        echo "Порт $PORT свободен."
    fi
}

check_and_free_port 443
check_and_free_port 8080

if command -v x-ui &> /dev/null; then
    echo "Обнаружена установленная панель x-ui."
    echo "Удаление x-ui..."
    /usr/local/x-ui/x-ui uninstall -y &>/dev/null || true
    rm -rf /usr/local/x-ui /etc/x-ui /usr/bin/x-ui /etc/systemd/system/x-ui.service
    systemctl daemon-reexec
    systemctl daemon-reload
    rm -f "$OUTPUT_FILE"
    echo "x-ui успешно удалена. Продолжаем выполнение скрипта..."
fi

echo "Установка 3x-ui..."
cd /usr/local/ || exit 1
ARCH=$(uname -m)

case "$ARCH" in
    x86_64) ARCH_DL="amd64" ;;
    aarch64) ARCH_DL="arm64" ;;
    armv7l) ARCH_DL="armv7" ;;
    *) echo "Неизвестная архитектура: $ARCH"; exit 1 ;;
esac

wget -q -O x-ui-linux-${ARCH}.tar.gz "https://github.com/MHSanaei/3x-ui/releases/download/v2.6.7/x-ui-linux-${ARCH_DL}.tar.gz"

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
echo "3x-ui установлена успешно!"

echo "Изменение логина и пароля..."
PASSWORD=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 12)
WEBPATH=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 12)
/usr/local/x-ui/x-ui setting -username "admin" -password "${PASSWORD}" -webBasePath "${WEBPATH}" -port "8080"

SERVER_IP=$(hostname -I | awk '{print $1}')

systemctl restart x-ui

{
    echo -e "\nПанель 3x-ui доступна по ссылке: http://$SERVER_IP:8080/$WEBPATH"
    echo -e "Логин: admin"
    echo -e "Пароль: $PASSWORD"
} | tee "$OUTPUT_FILE"

export url="http://$SERVER_IP:8080/$WEBPATH"
export username="admin"
export password="${PASSWORD}"