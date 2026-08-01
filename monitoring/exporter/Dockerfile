FROM python:3.12-alpine

RUN apk add --no-cache iptables

WORKDIR /app
COPY exporter.py /app/exporter.py
RUN chmod +x /app/exporter.py

ENV EXPORTER_LISTEN=0.0.0.0
ENV EXPORTER_PORT=9101
ENV EXPORTER_INTERVAL=5

EXPOSE 9101
CMD ["python3", "/app/exporter.py"]
