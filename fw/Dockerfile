FROM alpine:latest

RUN apk add --no-cache iptables ipset redsocks curl jq

COPY redsocks.conf /etc/redsocks.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
