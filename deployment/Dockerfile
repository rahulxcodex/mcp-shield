FROM python:3.11-slim

WORKDIR /app

# Install build dependencies if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy model artifacts and application code
COPY models/ ./models/
COPY app.py .

# Standard port for Hugging Face Spaces is 7860; Render passes $PORT
ENV PORT=7860
EXPOSE 7860

CMD ["python", "app.py"]
