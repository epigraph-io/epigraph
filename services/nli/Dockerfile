# CPU-only NLI cross-encoder service. Build is NOT exercised on the
# 2.7GB-free dev box (the torch+model layer needs more RAM/disk); it is a
# deployment artifact for the GPU/larger VM (see memory project_vm_gpu_upgrade).
FROM python:3.11-slim

WORKDIR /app

# System deps for sentencepiece / tokenizers build wheels.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py ./

# Pre-cache the model into the image so first request is not a cold pull.
# Skipped automatically when NLI_STUB=1 is set at build time.
ARG NLI_MODEL=MoritzLaurer/DeBERTa-v3-base-mnli-fever-anli
ENV NLI_MODEL=${NLI_MODEL}
RUN python -c "import os; \
  os.environ.get('NLI_STUB')=='1' or __import__('transformers').pipeline('text-classification', model=os.environ['NLI_MODEL'], top_k=None, device=-1)" || true

EXPOSE 8000
# 2 workers keeps RAM bounded; the model is loaded per-worker on first call.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
