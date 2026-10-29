FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && apt-get clean

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY migrations ./migrations
RUN pip install --no-cache-dir .

ENV CONSENTVAULT_MIGRATIONS=/app/migrations
RUN useradd --system --uid 10001 consentvault
USER consentvault

EXPOSE 8080
CMD ["consentvault", "serve", "--host", "0.0.0.0", "--port", "8080"]
