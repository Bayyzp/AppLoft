#  AppLoft - Minimal Prototype

This is a minimal prototype of a Node.js hosting platform written in Go.

## Features
- User register/login (SQLite)
- Upload zipped Node.js project (server-side)
- Attempts to `npm install` and run the app (tries `npm start` then `node index.js`)
- Reverse proxy by Host header to the app's allocated port

## IMPORTANT WARNINGS
- **Security:** This project runs untrusted code directly on the host. This is extremely dangerous in production.
  Use containerization (Docker/LXC) and strict resource limits before exposing publicly.
- **Requirements on host:**
  - Go 1.21+
  - Node.js and npm available in PATH
  - sqlite3 (bundled as lib via Go driver)
- **Ports:** The app allocates ports starting at 30000. Ensure your firewall allows these local ports.

## Quick deploy (example)
1. Build:
   ```
   go build -o nodehost
   ```
2. Run:
   ```
   ./nodehost
   ```
   The server listens on port 8080.

3. Point your custom domain's A record to the server IP and create an HTTP server/port forwarding so requests reach this Go server.
   The app will reverse-proxy requests based on the Host header.

## Notes
- This is a developer prototype. For a production-ready system you must:
  - Run each app inside isolated container (Docker)
  - Implement resource limits and user quotas
  - Use HTTPS (Caddy or Let's Encrypt)
  - Validate and sanitize uploads

## Docker-per-app helper (safer deployment pattern)

This repository now includes a helper script `scripts/run_app_container.sh` and a `docker-compose.yml`.

### Overview
- `nodehost` service runs the Go server (listens on 8080).
- `caddy` acts as a fronting reverse proxy (ports 80/443) and forwards requests to `nodehost`.
- Each uploaded app should be run in its own Docker container to provide isolation. This repo includes a **helper script** (not fully automatic) that starts a container for a given user/app and maps a host port to the container.

### How to run everything (development)
1. Build and start the services:
   ```
   docker compose build
   docker compose up -d
   ```
   > Note: This will mount `/var/run/docker.sock` into the nodehost container so it can interact with Docker. This is convenient but **very dangerous** (gives root-level access to Docker host). A safer option is to run the helper script from the host machine instead of inside the container.

2. Upload an app through the web UI (or place files into `apps/<user_id>/<appname>/`).

3. Start the app in a container (from host machine, recommended):
   ```
   ./scripts/run_app_container.sh <USER_ID> <APP_NAME> <HOST_PORT> [INTERNAL_PORT]
   ```
   Example:
   ```
   ./scripts/run_app_container.sh 2 myapp 31000 3000
   ```
   This will:
   - Bind-mount `./apps/2/myapp` into the official `node:18` image
   - Run `npm install --production`
   - Start `node index.js` inside the container
   - Expose the container on host port `31000`

4. Add a DNS record for your custom domain that points to the server IP, then in the `apps` table (or via dashboard) set the `domain` column to your custom hostname. The fronting Caddy will forward the Host header to nodehost which will route to the app port.

### Security notes (read carefully)
- Do **not** expose `/var/run/docker.sock` to untrusted code. Prefer running container orchestration from the host or via a dedicated service account.
- Use resource limits for containers (CPU, memory) — the helper script doesn't set these.
- Use non-root images for running apps where possible.
- Use a proper orchestration or sandbox (containerd, Kubernetes, Firecracker) for production workloads.


## Auto-start on upload

When a user uploads a ZIP and the server extracts it, the server will now
attempt to automatically start the app using `scripts/run_app_container.sh`.
The app will be exposed on the allocated host port (starting from 30000) and
Caddy will route requests by Host header to the corresponding port.



## Production hardening steps applied in this branch

The project now includes multiple production-focused measures:

1. **Upload validation & limits**
   - Max upload size: 25 MB.
   - Per-user app limit: 5 apps.
   - App names sanitized (only alphanumeric, -, _).
   - Requires `package.json` present (to ensure Node app).

2. **Build-per-app Docker image**
   - Each upload is built into a Docker image inside the app directory (minimal runtime Dockerfile).
   - The runtime image runs as a non-root user (`appuser`).

3. **Strict runtime flags**
   - Containers launched with:
     - `--read-only`, `--tmpfs /tmp`, `--cap-drop ALL`, `--security-opt no-new-privileges`
     - `--pids-limit` to limit process count
     - Memory and CPU limits (`--memory`, `--cpus`)
     - Run as non-root user (`--user 1000:1000`)
   - Consider applying AppArmor or SELinux profiles and a custom seccomp JSON for further restrictions.

4. **Avoid exposing Docker socket**
   - This setup builds images and runs containers but **does not** require the Go service to have direct access to the host Docker socket if you run the helper script from the host.
   - If you must allow the Go service to launch containers, use a docker API proxy with restricted permissions or a dedicated service account.

5. **Network isolation**
   - Use user-defined Docker networks and firewall rules to isolate app containers from sensitive infrastructure (databases, metadata services).
   - Consider using an ingress proxy (Caddy/Traefik) that performs TLS termination and request filtering.

6. **Monitoring & quotas**
   - Track container statuses in DB (apps table includes status and container_name).
   - Add alerting for high CPU/memory, and implement disk quotas for user uploads.

7. **Scanning & sandboxing**
   - For production, incorporate malware scanning and static-analysis of uploaded contents.
   - Use kernel-level virtualization (gVisor, Firecracker) or orchestrators (Kubernetes) for stronger isolation.

