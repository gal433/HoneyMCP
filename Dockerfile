FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY honeypot ./honeypot
COPY analyze.py smoke_test.py ./

# Railway injects PORT; default to 8000 locally.
ENV PORT=8000
EXPOSE 8000

CMD ["python", "-m", "honeypot.server"]
