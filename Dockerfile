FROM rust:latest

WORKDIR /app

COPY target/kms-secret-service .

CMD ["./kms-secret-service"]