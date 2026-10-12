FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Copy application code
COPY . .

# Run training to generate local models if not already present
RUN python -m training.train && python -m training.evaluate

EXPOSE 8000 8501

CMD ["uvicorn", "threatsense.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
