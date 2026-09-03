# Dockerfile - kwa ajili ya Google Cloud Run
FROM python:3.12-slim

# Epuka kuandika faili za .pyc na kuwezesha logs za moja kwa moja
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Sakinisha dependencies kwanza (inasaidia Docker cache iwe na ufanisi
# zaidi - hazitasakinishwa upya kila unapobadilisha code tu)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Nakili code yote ya app
COPY . .

# Cloud Run inatoa PORT kupitia environment variable (kawaida 8080)
ENV PORT=8080
EXPOSE 8080

# Anzisha na Gunicorn - "exec form" inayosoma $PORT wakati wa kuanza
CMD exec gunicorn --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 60 wsgi:app
