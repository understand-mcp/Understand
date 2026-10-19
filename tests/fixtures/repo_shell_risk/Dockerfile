FROM python:3.12-slim
ENV API_KEY=supersecretvalue123456
COPY . /app
RUN chmod 777 /app
CMD ["python", "-m", "app.api"]
