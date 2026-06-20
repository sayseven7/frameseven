FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      chromium \
      fonts-dejavu-core \
      fonts-liberation \
      gcc \
      libc6-dev \
      nmap \
      python3 \
      python3-venv \
      sqlmap && \
    rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/frameseven-python && \
    /opt/frameseven-python/bin/python -m pip install --no-cache-dir --upgrade pip && \
    /opt/frameseven-python/bin/python -m pip install --no-cache-dir "fpdf2>=2.8"

RUN useradd --create-home --uid 1000 --shell /bin/sh frameseven && \
    mkdir -p /workspace && \
    chown -R frameseven:frameseven /workspace /home/frameseven

COPY --chmod=0755 bin/frameseven /usr/local/bin/frameseven
COPY --chmod=0755 bin/frameseven-mcp /usr/local/bin/frameseven-mcp

ENV FRAMESEVEN_PYTHON=/opt/frameseven-python/bin/python

WORKDIR /workspace
USER frameseven

ENTRYPOINT ["frameseven"]
