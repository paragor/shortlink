FROM alpine:3.20.2

WORKDIR /app

COPY shortlink /usr/bin/
ENTRYPOINT ["/usr/bin/shortlink"]
