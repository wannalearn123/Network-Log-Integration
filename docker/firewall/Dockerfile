FROM alpine:latest

RUN apk add --no-cache \
    nftables \
    bash

COPY nftables.conf /etc/nftables.conf
COPY log_generator.sh /log_generator.sh
RUN chmod +x /log_generator.sh

RUN touch /var/log/messages

# Start syslogd FIRST so nftables log messages get captured
CMD syslogd -R 172.20.0.10:514 && \
    nft -f /etc/nftables.conf && \
    echo "[firewall] nftables rules loaded" && \
    /log_generator.sh && \
    tail -f /var/log/messages
