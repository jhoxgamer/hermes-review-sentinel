# Multi-stage build for hermes-review-sentinel
FROM python:3.12-slim as builder

WORKDIR /app

# Install build dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Copy project files
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY rules/ ./rules/

# Install in development mode
RUN pip install --no-cache-dir -e .

# Final stage
FROM python:3.12-slim

WORKDIR /app

# Copy from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/hermes-sentinel /usr/local/bin/hermes-sentinel

# Copy source for runtime (rules, etc.)
COPY rules/ /app/rules/

# Non-root user
RUN useradd -m -u 1000 sentinel && chown -R sentinel:sentinel /app
USER sentinel

ENTRYPOINT ["hermes-sentinel"]
CMD ["--help"]