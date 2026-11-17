# poll-relay — works on Render, Koyeb, Fly, Railway, Cloud Run, or any VPS.
FROM python:3.12-slim
# openssl is needed for ed25519 signature verification (slim ships it, pinned here)
RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY signing.py relay.py ./
# free hosts usually wipe the filesystem; mount a volume at /data (optional)
ENV DATA_FILE=/data/relay-state.json
RUN mkdir -p /data
ENV PORT=8080
EXPOSE 8080
CMD ["python3", "relay.py"]
