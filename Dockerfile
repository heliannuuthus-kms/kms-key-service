FROM rust:latest

WORKDIR /app

COPY target/release/haauth-server .

CMD ["./haauth-server"]