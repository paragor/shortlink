FROM alpine:3.20.2

WORKDIR /app

COPY app /usr/bin/
ENTRYPOINT ["/usr/bin/app"]
