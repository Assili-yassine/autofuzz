# AutoFuzz — self-contained image with every external recon tool it
# orchestrates (httpx, katana, gau, wayback, ffuf, linkfinder) plus AutoFuzz
# itself installed as the `autofuzz` command.
#
# Build:
#   docker build -t autofuzz .
#
# Run (results land in ./results on your HOST machine, via the bind mount):
#   docker run --rm -v "$(pwd):/work" autofuzz -d https://example.com --json
#   docker run --rm -v "$(pwd):/work" autofuzz -i domains.txt --html
#
# Only run against assets you own or are explicitly authorized to test.

# ---- Stage 1: compile the Go-based recon tools ------------------------------
FROM golang:1.22-bookworm AS gobuild

RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/ffuf/ffuf/v2@latest

# ---- Stage 2: final image ----------------------------------------------------
FROM python:3.12-slim

# Go binaries. AutoFuzz expects a binary literally named `wayback` (not
# `waybackurls`), so it's renamed here at build time.
COPY --from=gobuild /go/bin/httpx /go/bin/katana /go/bin/gau /go/bin/waybackurls /go/bin/ffuf /usr/local/bin/
RUN mv /usr/local/bin/waybackurls /usr/local/bin/wayback

# LinkFinder, installed as an executable named `linkfinder` on PATH.
RUN apt-get update && apt-get install -y --no-install-recommends git && \
    git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git /opt/linkfinder && \
    pip install --no-cache-dir --break-system-packages -r /opt/linkfinder/requirements.txt && \
    printf '#!/usr/bin/env bash\nexec python3 /opt/linkfinder/linkfinder.py "$@"\n' > /usr/local/bin/linkfinder && \
    chmod +x /usr/local/bin/linkfinder && \
    apt-get purge -y git && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# AutoFuzz itself, as a real global `autofuzz` command.
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir --break-system-packages .

# The directory a container run mounts to — results are written here
# (relative "results/" output_dir), which shows up on the host via -v.
WORKDIR /work

ENTRYPOINT ["autofuzz"]
CMD ["--help"]
