# Dockerfile for running enforcement integration tests
#
# Build:
#   docker build -t boundary-daemon-tests -f tests/integration/Dockerfile .
#
# Run tests (from project root):
#   docker run --privileged --rm boundary-daemon-tests
#
# Run specific tests:
#   docker run --privileged --rm boundary-daemon-tests pytest tests/integration/test_enforcement_integration.py -v -k "network"
#
# Interactive debugging:
#   docker run --privileged --rm -it boundary-daemon-tests bash

FROM python:3.11-slim

# Pinned snapshot for reproducibility (update periodically)
LABEL maintainer="boundary-daemon" \
      description="Integration test image for boundary-daemon enforcement modules"

# Install only required system packages; clean up in the same layer
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    iproute2 \
    procps \
    udev \
    libseccomp-dev \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Set working directory
WORKDIR /app

# Copy requirements first for caching
COPY requirements.txt requirements-dev.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt -r requirements-dev.txt

# Copy project
COPY . .

# Install project in development mode
RUN pip install -e .

# Create non-root user for test execution.
# Note: --privileged is still required for iptables/network tests,
# but running as non-root limits blast radius of test code.
RUN groupadd --gid 1000 testrunner && \
    useradd --uid 1000 --gid testrunner --shell /bin/bash testrunner && \
    chown -R testrunner:testrunner /app
USER testrunner

# Default: run enforcement integration tests
CMD ["pytest", "tests/integration/test_enforcement_integration.py", "-v", "--tb=short"]
