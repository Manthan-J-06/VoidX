FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py dashboard.html ./

EXPOSE 8000

ENV RUNNING_IN_CONTAINER=true

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
