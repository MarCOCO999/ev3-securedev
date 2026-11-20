FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Necesario para que /metrics funcione con debug=True
ENV DEBUG_METRICS=1

EXPOSE 5000
CMD ["python", "app.py"]
