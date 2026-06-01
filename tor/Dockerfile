FROM alpine:3.22

# Install required packages
RUN apk add --no-cache tor lyrebird

# Copy configuration files
COPY ./torrc /etc/tor/torrc
COPY ./bridges.txt /etc/tor/bridges.txt
COPY ./docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Make the entrypoint script executable
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Expose the SOCKS and control ports
EXPOSE 9050
EXPOSE 9051

# Set the working directory
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Start Tor
CMD ["tor", "-f", "/etc/tor/torrc"]