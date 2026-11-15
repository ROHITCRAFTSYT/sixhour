FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 HOST=0.0.0.0 PORT=8080
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd -m app
USER app
EXPOSE 8080
CMD ["sixhour"]
