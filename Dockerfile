# syntax=docker/dockerfile:1

FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY dnsrace ./dnsrace
COPY examples ./examples
RUN pip install --no-cache-dir .

ENTRYPOINT ["dnsrace"]
CMD ["--help"]