FROM rust:1.82-bookworm
RUN apt-get update && apt-get install -y python3 python3-pytest pkg-config libssl-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev libfontconfig1-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN cargo test --workspace --exclude vusi-gui --no-run
CMD ["sh", "-c", "cargo test --workspace --exclude vusi-gui && pytest atxqu/"]
