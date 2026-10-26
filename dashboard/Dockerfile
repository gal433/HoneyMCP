# Dashboard image: built from the repo root, but only copies the dashboard, so
# none of the honeypot code ends up in this service.
FROM python:3.12-slim

WORKDIR /app

COPY dashboard/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dashboard/app.py ./

ENV PORT=8080
EXPOSE 8080

CMD ["python", "app.py"]
