# Single-container packaging of the lab: simulators, tap, and detection
# engine all run as separate processes inside one container, coordinated by
# the Makefile targets. See docs/architecture.md for why this repo currently
# simulates multiple lab "hosts" via distinct loopback addresses inside one
# process space rather than one container per host, and what moving to true
# per-host containers (docker-compose with a dedicated bridge network) would
# change.
FROM python:3.11-slim

WORKDIR /app

# git is needed only to install the trustgraph dependency (a pinned git
# commit, see requirements.txt); make runs the lab.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git make \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as non-root. The lab only needs to bind unprivileged ports (>1024)
# and write its own logs/ directory. (The network-segmentation scenario
# needs CAP_NET_ADMIN and is run on the host, not in this image.)
RUN useradd --create-home --uid 10001 lab \
    && mkdir -p logs \
    && chown -R lab:lab /app/logs
USER lab

# Inside the container the tap must listen on all interfaces so Docker can
# publish its ports; docker-compose.yml publishes them on the host's
# 127.0.0.1 only. The simulators behind the tap stay on loopback.
ENV LAB_BIND_HOST=0.0.0.0 \
    PYTHONUNBUFFERED=1

CMD ["bash", "-c", "make lab-up && sleep infinity"]
