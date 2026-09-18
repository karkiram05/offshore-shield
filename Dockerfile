# Single-container packaging of the lab: simulators, tap, and detection
# engine all run as separate processes inside one container, coordinated by
# the Makefile targets. See docs/architecture.md for why this repo currently
# simulates multiple lab "hosts" via distinct loopback addresses inside one
# process space rather than one container per host, and what moving to true
# per-host containers (docker-compose with a dedicated bridge network) would
# change.
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["bash", "-c", "make lab-up && sleep infinity"]
