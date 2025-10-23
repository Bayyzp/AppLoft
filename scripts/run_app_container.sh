#!/usr/bin/env bash
set -eu

# Usage: ./run_app_container.sh <USER_ID> <APP_NAME> <HOST_PORT> [INTERNAL_PORT] [MEMORY] [CPUS]
USER_ID="$1"
APP_NAME="$2"
HOST_PORT="$3"
INTERNAL_PORT="${4:-3000}"
MEMORY="${5:-256m}"
CPUS="${6:-0.5}"

APP_DIR="./apps/${USER_ID}/${APP_NAME}"
IMAGE_TAG="nodeapp_${USER_ID}_${APP_NAME}:${RANDOM}"
CONTAINER_NAME="app_${USER_ID}_${APP_NAME}"

if [ ! -d "$APP_DIR" ]; then
  echo "App directory not found" >&2
  exit 1
fi

# create a minimal Dockerfile in app dir to run the app as non-root user
cat > "${APP_DIR}/Dockerfile.runtime" <<'DOCK'
FROM node:18-slim
# create non-root user
RUN useradd -m appuser
WORKDIR /srv
COPY . .
RUN chown -R appuser:appuser /srv
USER appuser
# install production deps
RUN if [ -f package.json ]; then npm install --production; fi
EXPOSE 3000
CMD ["node", "index.js"]
DOCK

# build image (no cache)
docker build --no-cache -t "${IMAGE_TAG}" -f "${APP_DIR}/Dockerfile.runtime" "${APP_DIR}" >/tmp/docker_build_${USER_ID}_${APP_NAME}.log 2>&1 || { cat /tmp/docker_build_${USER_ID}_${APP_NAME}.log >&2; exit 2; }

# remove existing container
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
  docker rm -f "${CONTAINER_NAME}" >/dev/null || true
fi

# run with strict security options
docker run -d --name "${CONTAINER_NAME}"   -p "${HOST_PORT}:${INTERNAL_PORT}"   --memory "${MEMORY}"   --cpus "${CPUS}"   --pids-limit=64   --read-only   --tmpfs /tmp:rw,size=64m   --security-opt no-new-privileges   --cap-drop ALL   --network bridge   --user 1000:1000   --restart unless-stopped   "${IMAGE_TAG}" >/dev/null

if [ $? -ne 0 ]; then
  echo "failed" >&2
  exit 3
fi

echo "${CONTAINER_NAME}"
