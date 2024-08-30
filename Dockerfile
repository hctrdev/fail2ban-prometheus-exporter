FROM golang:1.23-bullseye AS build

# Create build workspace folder
WORKDIR /workspace
ADD . /workspace

# Install updates and build tools
RUN apt update --yes && \
    apt install --yes build-essential

# Build the actual binary
RUN make build

# -- -- -- -- -- --

# Set up image to run the tool
FROM alpine

# Create main app folder to run from
WORKDIR /app

# Copy built binary from build image
COPY --from=build /workspace/fail2ban_exporter /app

# Setup a healthcheck
COPY health /app/health
RUN apk add curl
HEALTHCHECK --interval=10s --timeout=4s --retries=3 CMD /app/health

ENTRYPOINT ["/app/fail2ban_exporter"]
