#!/bin/bash
sudo yum install docker -y
sudo service docker start

# Make docker  autostart
sudo chkconfig docker on

# Install git
sudo yum install -y git

# docker-compose (latest version)
sudo curl -L https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m) -o /usr/local/bin/docker-compose

# Fix permissions after download
sudo chmod +x /usr/local/bin/docker-compose

# Verify installation success
docker-compose version