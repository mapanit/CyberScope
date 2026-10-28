#!/bin/bash

set -Eeuo pipefail

trap 'status=$?; echo "Установка завершилась ошибкой на строке ${BASH_LINENO[0]} (код ${status})." >&2; exit "$status"' ERR

echo "Начинаем установку инструментов..."

# Проверяем необходимые условия до начала установки.
if ! command -v go >/dev/null 2>&1; then
    echo "Ошибка: Go не установлен или отсутствует в PATH." >&2
    exit 1
fi

go version

GO_BIN_DIR="$(go env GOBIN)"
if [[ -z "$GO_BIN_DIR" ]]; then
    GO_BIN_DIR="$(go env GOPATH)/bin"
fi

mkdir -p "$GO_BIN_DIR"
if [[ ! -w "$GO_BIN_DIR" ]]; then
    echo "Ошибка: каталог для Go-инструментов недоступен для записи: $GO_BIN_DIR" >&2
    exit 1
fi

export PATH="$GO_BIN_DIR:$PATH"

# Установка версий Go-инструментов, синхронизированных с backend/Dockerfile.api.
go install github.com/projectdiscovery/katana/cmd/katana@v1.8.0
go install github.com/owasp-amass/amass/v5/cmd/amass@v5.1.3
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1
go install github.com/hahwul/dalfox/v2@v2.12.0
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.17.0
go install github.com/projectdiscovery/httpx/cmd/httpx@v1.12.0
go install github.com/kacakb/jsfinder@0fe0014f806bb041297b0a0d2aed46ae7359122f
go install github.com/tomnomnom/waybackurls@v0.1.0
go install github.com/OJ/gobuster/v3@v3.8.2

GO_BIN_PATH_LINE="export PATH=\"$GO_BIN_DIR:\$PATH\""
if [[ -f "$HOME/.bashrc" ]] && ! grep -Fqx "$GO_BIN_PATH_LINE" "$HOME/.bashrc"; then
    printf '%s\n' "$GO_BIN_PATH_LINE" >> "$HOME/.bashrc"
fi

echo "Установка завершена!"
echo "Настройка завершена!"