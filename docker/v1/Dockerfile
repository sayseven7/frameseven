ARG GO_VERSION=1.26.4

FROM golang:${GO_VERSION}-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=development
RUN version="${VERSION#v}" && \
    CGO_ENABLED=0 go build \
      -trimpath \
      -ldflags="-s -w -X main.buildVersion=${version}" \
      -o /out/frameseven \
      ./cmd/cli/v1 && \
    CGO_ENABLED=0 go build \
      -trimpath \
      -ldflags="-s -w" \
      -o /out/frameseven-mcp \
      ./cmd/mcp

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      chromium \
      fonts-dejavu-core \
      fonts-liberation \
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

COPY --from=build /out/frameseven /usr/local/bin/frameseven
COPY --from=build /out/frameseven-mcp /usr/local/bin/frameseven-mcp

ENV FRAMESEVEN_PYTHON=/opt/frameseven-python/bin/python

WORKDIR /workspace
USER frameseven

ENTRYPOINT ["frameseven"]
