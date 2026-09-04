FROM alpine:latest

RUN apk add --no-cache \
    iptables \
    iproute2 \
    bash

COPY iptables-rules.sh /iptables-rules.sh
RUN chmod +x /iptables-rules.sh

RUN touch /var/log/messages

# Start syslogd FIRST so iptables LOG messages get captured
CMD syslogd -R 172.20.0.10:514 && \
    /iptables-rules.sh && \
    tail -f /var/log/messages
