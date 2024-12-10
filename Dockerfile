FROM registry.redhat.io/ubi9/go-toolset:1.22.7 as builder

USER 0
WORKDIR /opt/app-root/src

# Generate self-signed certificate
RUN mkdir -p /certs && \
    openssl req -x509 \
        -newkey rsa:4096 \
        -keyout /certs/tls.key \
        -out /certs/tls.crt \
        -days 365 \
        -nodes \
        -subj "/CN=pmtud-test"

# Copy the source code
COPY . .

# Build with VCS stamping disabled
RUN go build -buildvcs=false -o pmtud-test

# Use minimal RHEL 9 image for runtime
FROM registry.redhat.io/ubi9-minimal:9.5

# Create certificates directory
RUN mkdir -p /certs

# Copy the binary and certificates
COPY --from=builder /opt/app-root/src/pmtud-test /pmtud-test
COPY --from=builder /certs/tls.crt /certs/tls.crt
COPY --from=builder /certs/tls.key /certs/tls.key

# Set necessary permissions for OpenShift
RUN chgrp -R 0 /certs && \
    chmod -R g=u /certs
USER 1001

EXPOSE 8443
CMD ["/pmtud-test"]
