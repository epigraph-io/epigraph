# CPU-only NLI cross-encoder service. Build is NOT exercised on the
# 2.7GB-free dev box (the torch+model layer needs more RAM/disk); it is a
# deployment artifact for the GPU/larger VM (see memory project_vm_gpu_upgrade).
# The build steps are checked without Docker by test_dockerfile.py.
FROM python:3.11-slim

WORKDIR /app

# System deps for sentencepiece / tokenizers build wheels.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
# torch from the PyTorch CPU wheel index, at the version requirements.txt pins:
# the default PyPI wheel on Linux pulls the CUDA libraries (several GB) into
# this CPU-only image. Only the torch wheel comes from that index: --index-url
# (not --extra-index-url) and --no-deps, so torch's own dependencies resolve
# from PyPI in the next step (the CPU index carries stale copies of some, e.g.
# setuptools). The installed 2.x.y+cpu satisfies the torch==2.x.y line there,
# so pip keeps it.
RUN pip install --no-cache-dir --no-deps --index-url https://download.pytorch.org/whl/cpu \
      "$(grep -E '^torch==' requirements.txt)"
RUN pip install --no-cache-dir -r requirements.txt
# Fail the build if a CUDA build of torch ended up installed anyway.
RUN python -c "import sys, torch; \
  sys.exit(None if torch.version.cuda is None else 'CUDA torch ' + torch.__version__ + ' installed; expected the CPU wheel')"

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
