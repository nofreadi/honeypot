FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev gcc \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir opencanary

RUN mkdir -p /etc/opencanaryd /var/log/opencanary

COPY opencanary.conf /etc/opencanaryd/opencanary.conf

EXPOSE 80 3306

CMD ["opencanaryd", "--dev"]
