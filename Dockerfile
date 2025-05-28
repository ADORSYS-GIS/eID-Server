FROM ubuntu:22.04

# Install required packages
RUN apt-get update && apt-get install -y \
    xmlsec1 \
    libxmlsec1-dev \
    libxml2-dev \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Create a working directory
WORKDIR /app

# Set the default command
CMD ["/bin/bash"] 