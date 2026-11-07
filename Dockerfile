FROM python:3.12-slim
WORKDIR /app
# no pip install: the backend uses the Python standard library only
COPY analyzer ./analyzer
COPY static ./static
COPY server.py ./
ENV PYTHONUNBUFFERED=1 HOST=0.0.0.0 PORT=8000
EXPOSE 8000
CMD ["python", "server.py"]