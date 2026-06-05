#!/bin/bash
set -e

echo "Run fediverse-gateway deploy script"

echo "GITHUB_TOKEN: ${GITHUB_TOKEN:0:4}... (truncated for security)"

if [ -z "$GITHUB_TOKEN" ]; then
  echo "Error: GITHUB_TOKEN is not set"
  exit 1
fi

echo "$GITHUB_TOKEN" | docker login ghcr.io -u filinvadim --password-stdin
docker pull ghcr.io/warp-net/warpnet-gateway:latest

mkdir -p /root/gateway-testnet
mv docker-compose-testnet.yml gateway-testnet/docker-compose-testnet.yml
docker compose -p warpnet-gateway-testnet -f gateway-testnet/docker-compose-testnet.yml down --remove-orphans
docker compose -p warpnet-gateway-testnet -f gateway-testnet/docker-compose-testnet.yml up -d
docker image prune --force
