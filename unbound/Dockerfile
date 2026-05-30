FROM alpine:3.21

RUN apk add --no-cache \ 
    unbound \
    ca-certificates

COPY ./unbound.conf /etc/unbound/unbound.conf

EXPOSE 53/tcp 53/udp

CMD ["unbound","-d", "-c", "/etc/unbound/unbound.conf"]
