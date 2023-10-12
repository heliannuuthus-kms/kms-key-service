FROM rust:latest

WORKDIR /app

COPY target/release/kms-secret-service .

CMD ["./kms-secret-service"]