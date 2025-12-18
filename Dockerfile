FROM python:3.11-slim

WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app/server.py .
COPY app/index.html .

EXPOSE 5000

CMD ["python", "server.py"]
