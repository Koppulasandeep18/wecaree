# Production Dockerfile for WE CARE Water Technology Platform
FROM python:3.11-slim

WORKDIR /app

# Ensure standard output and error are sent straight to logs
ENV PYTHONUNBUFFERED=1
ENV PORT=8080

# Copy application files
COPY . /app

# Expose HTTP port
EXPOSE 8080

# Dedicated volume for SQLite data persistence across redeployments
VOLUME ["/app/data"]

# Run the high-performance multi-threaded server
CMD ["python", "server.py"]
