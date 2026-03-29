#!/bin/bash

# Простой скрипт установки

echo "Начинаем установку инструментов..."

# Добавляем ~/go/bin в PATH для текущей сессии
export PATH=$PATH:~/go/bin

# Установка Go инструментов
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/owasp-amass/amass/v5/cmd/amass@main
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/hahwul/dalfox/v2@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/kacakb/jsfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/OJ/gobuster/v3@latest


echo "Установка завершена!"
echo "Не забудьте добавить ~/go/bin в PATH: export PATH=\$PATH:~/go/bin"