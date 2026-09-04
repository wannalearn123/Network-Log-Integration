FROM alpine:latest

RUN apk add --no-cache \
    bridge-utils \
    iproute2 \
    bash

COPY setup-bridge.sh /setup-bridge.sh
RUN chmod +x /setup-bridge.sh

RUN touch /var/log/messages

CMD /setup-bridge.sh && \
    syslogd -R 172.20.0.10:514 && \
    tail -f /var/log/messages
