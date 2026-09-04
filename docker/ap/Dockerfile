FROM alpine:latest

RUN apk add --no-cache \
    bash

COPY auth_sim.sh /auth_sim.sh
RUN chmod +x /auth_sim.sh

RUN touch /var/log/messages

CMD /auth_sim.sh && \
    syslogd -R 172.20.0.10:514 && \
    tail -f /var/log/messages
