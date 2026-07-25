FROM python:3.11-slim

# System dependencies install karo (Tesseract OCR + zbar for QR codes)
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    libzbar0 \
    libgl1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Tesseract ka path Linux me alag hota hai Windows se
ENV TESSERACT_CMD=/usr/bin/tesseract

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000"]