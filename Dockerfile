FROM python:3.12-slim AS base

LABEL maintainer="CypherSec <cyphersec.404@gmail.com>"
LABEL description="ReconStrike — Isolated vulnerability scanner"

RUN groupadd -r scanner && useradd -r -g scanner -d /app -s /usr/sbin/nologin scanner

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir cryptography>=42.0.0

COPY . .

RUN mkdir -p /app/output /app/.reconstrike && \
    chown -R scanner:scanner /app

USER scanner

ENTRYPOINT ["python3", "reconstrike.py"]
CMD ["--help"]
