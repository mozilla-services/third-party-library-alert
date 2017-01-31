#!/bin/bash -vex

apt-get update
apt-get install -y python python-requests python-feedparser git curl wget

cd /home/worker/workspace
git clone https://github.com/mozilla-services/third-party-library-alert.git
