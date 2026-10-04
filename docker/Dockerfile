# Jeden obraz dla gatewaya, mocków i testów (różnią się tylko komendą).
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HF_HOME=/home/aicl/.cache/huggingface

# Utwórz nieuprzywilejowanego użytkownika
RUN useradd -u 10001 -m -s /bin/bash aicl && \
    mkdir -p /app/data /home/aicl/.cache/huggingface && \
    chown -R aicl:aicl /app /home/aicl

COPY --chown=aicl:aicl . .

# Optional extras, e.g. AICL_EXTRAS=test,protectai,redis docker compose build (default: test only)
ARG EXTRAS=test
RUN pip install --no-cache-dir -e ".[${EXTRAS}]" && \
    chown -R aicl:aicl /app/data /home/aicl

USER aicl
EXPOSE 8080
CMD ["uvicorn", "aicl.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080"]
