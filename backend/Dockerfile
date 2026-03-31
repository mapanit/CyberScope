FROM python:3.11-slim

WORKDIR /app

# Установка системных зависимостей и Go
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    git \
    wget \
    golang-go \
    && rm -rf /var/lib/apt/lists/*

# Установка Go инструментов для сканирования безопасности
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/owasp-amass/amass/v5/cmd/amass@main && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/kacakb/jsfinder@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/OJ/gobuster/v3@latest && \
    cp /root/go/bin/* /usr/local/bin/

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /app/reports

EXPOSE 8000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
