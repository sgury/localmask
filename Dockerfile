FROM python:3.11-slim

WORKDIR /app

# Install git (needed for repo cloning feature)
RUN apt-get update && apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# Install Python deps first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    python -m spacy download en_core_web_sm

# Copy app code
COPY *.py *.html ./

# Pre-download the DistilBERT model so first request isn't slow
RUN python -c "from transformers import AutoTokenizer, AutoModelForSequenceClassification; \
    AutoTokenizer.from_pretrained('distilbert-base-uncased'); \
    AutoModelForSequenceClassification.from_pretrained('distilbert-base-uncased', num_labels=2)"

EXPOSE 8000

ENV LOCALMASK_HOST=0.0.0.0
ENV LOCALMASK_PORT=8000

CMD ["python", "server.py"]
