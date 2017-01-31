FROM ubuntu:16.04

# Add setup script
ADD build-image.sh      /usr/local/bin/build-image.sh

# Setup a workspace that won't use AUFS
VOLUME /home/worker/workspace

# Set variable normally configured at login, by the shells parent process, these
# are taken from GNU su manual
ENV           HOME          /home/worker
ENV           SHELL         /bin/bash
ENV           USER          worker
ENV           LOGNAME       worker
ENV           HOSTNAME      taskcluster-worker
ENV           LC_ALL        C

# Create worker user
RUN useradd -d /home/worker -s /bin/bash -m worker

# Set some sane defaults
WORKDIR /home/worker/

# Run setup script
RUN bash /usr/local/bin/build-image.sh

