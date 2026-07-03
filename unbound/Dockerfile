FROM alpine:3.22

RUN apk add --no-cache \ 
    unbound \
    ca-certificates

COPY ./unbound.conf /etc/unbound/unbound.conf
COPY ./entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN mkdir -p /var/lib/unbound && chown unbound:unbound /var/lib/unbound

EXPOSE 53/tcp 53/udp

ENTRYPOINT ["/entrypoint.sh"]
