FROM rust:latest

WORKDIR /app

COPY target/release/kms-key-service .

CMD ["./kms-key-service"]