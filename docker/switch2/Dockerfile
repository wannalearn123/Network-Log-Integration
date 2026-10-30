FROM alpine:3.22
RUN apk add --no-cache bash
RUN touch /var/log/messages
COPY log_generator.sh /log_generator.sh
RUN chmod +x /log_generator.sh
CMD syslogd -R 172.20.0.10:514 && /log_generator.sh && tail -f /var/log/messages
