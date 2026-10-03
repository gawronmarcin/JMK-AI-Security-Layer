# Jeden obraz dla gatewaya, mocków i testów (różnią się tylko komendą).
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY . .
RUN pip install --no-cache-dir -e ".[test]"
EXPOSE 8080
CMD ["uvicorn", "aicl.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080"]
