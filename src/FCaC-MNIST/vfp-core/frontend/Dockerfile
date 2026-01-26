# frontend/Dockerfile

FROM python:3.10-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn requests

# Copy application files
COPY app.py .
COPY static/ static/

EXPOSE 80

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "80"]