FROM registry.access.redhat.com/rhel9/go-toolset:1.22.7 as builder

USER 0
WORKDIR /opt/app-root/src

# Copy the source code
COPY . .

# Build the application
RUN go build -o pmtud-test

# Use minimal RHEL 9 image for runtime
FROM registry.access.redhat.com/ubi-minimal:9.5

# Copy the binary from builder
COPY --from=builder /opt/app-root/src/pmtud-test /pmtud-test

# Set necessary permissions for OpenShift
USER 1001

EXPOSE 8080
CMD ["/pmtud-test"]
