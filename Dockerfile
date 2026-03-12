FROM python:3.12-slim

WORKDIR /app

# Install uv
RUN pip install --no-cache-dir uv

# Copy project files
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install the package
RUN uv pip install --system .

# API key passed at runtime via environment variable
ENV ARKFORGE_API_KEY=""
ENV ARKFORGE_BASE_URL="https://trust.arkforge.tech"

ENTRYPOINT ["arkforge-mcp"]
