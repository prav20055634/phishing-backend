FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

WORKDIR /app/backend

CMD gunicorn -w 2 -b 0.0.0.0:$PORT --timeout 120 app:app