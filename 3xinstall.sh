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
    rm /root/3x-ui.txt
    echo "x-ui успешно удалена. Продолжаем выполнение скрипта..."
fi

PORT=8080

gen_random_string() {
    local length="$1"
    LC_ALL=C tr -dc 'a-zA-Z0-9' </dev/urandom | fold -w "$length" | head -n 1
}
USERNAME=$(gen_random_string 10)
PASSWORD=$(gen_random_string 10)
WEBPATH=$(gen_random_string 18)

if [[ $EUID -ne 0 ]]; then
    echo -e "${red}Ошибка:${plain} скрипт нужно запускать от root"
    exit 1
fi

if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    release=$ID
else
    echo "Не удалось определить ОС"
    exit 1
fi

arch() {
    case "$(uname -m)" in
        x86_64 | x64 | amd64) echo 'amd64' ;;
        i*86 | x86) echo '386' ;;
        armv8* | arm64 | aarch64) echo 'arm64' ;;
        armv7* | arm) echo 'armv7' ;;
        armv6*) echo 'armv6' ;;
        armv5*) echo 'armv5' ;;
        s390x) echo 's390x' ;;
        *) echo "unknown" ;;
    esac
}
ARCH=$(arch)

case "${release}" in
    ubuntu | debian | armbian)
        apt-get update > /dev/null
        apt-get install -y -q wget curl tar tzdata jq xxd > /dev/null
        ;;
    centos | rhel | almalinux | rocky | ol)
        yum -y update > /dev/null
        yum install -y -q wget curl tar tzdata jq xxd > /dev/null
        ;;
    fedora | amzn | virtuozzo)
        dnf -y update > /dev/null
        dnf install -y -q wget curl tar tzdata jq xxd > /dev/null
        ;;
    arch | manjaro | parch)
        pacman -Syu --noconfirm > /dev/null
        pacman -S --noconfirm wget curl tar tzdata jq xxd > /dev/null
        ;;
    opensuse-tumbleweed)
        zypper refresh > /dev/null
        zypper install -y wget curl tar timezone jq xxd > /dev/null
        ;;
    *)
        apt-get update > /dev/null
        apt-get install -y wget curl tar tzdata jq xxd > /dev/null
        ;;
esac

# Установка x-ui
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

/usr/local/x-ui/x-ui setting -username "$USERNAME" -password "$PASSWORD" -port "$PORT" -webBasePath "$WEBPATH"
/usr/local/x-ui/x-ui migrate

systemctl daemon-reload
systemctl enable x-ui
systemctl start x-ui

SERVER_IP=${SERVER_IP:-$(curl -s --max-time 3 https://api.ipify.org || curl -s --max-time 3 https://4.ident.me)}

echo -e "\n\033[1;32mПанель управления 3X-UI доступна по следующим данным:"
echo -e "Адрес панели: http://${SERVER_IP}:${PORT}/${WEBPATH}"
echo -e "Логин:        ${USERNAME}"
echo -e "Пароль:       ${PASSWORD}"

{
  echo "Панель управления 3X-UI доступна по следующим данным:"
  echo "Адрес панели - http://${SERVER_IP}:${PORT}/${WEBPATH}"
  echo "Логин:         ${USERNAME}"
  echo "Пароль:        ${PASSWORD}"
  echo ""
  echo "Инструкции по настройке VPN приложений:"
  echo "https://wiki.yukikras.net/ru/nastroikavpn"
} >> /root/3x-ui.txt

export url="http://$SERVER_IP:8080/$WEBPATH"
export username="${USERNAME}"
export password="${PASSWORD}"