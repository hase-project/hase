FROM ubuntu:16.04
MAINTAINER Emilio Coppa <ercoppa@gmail.com>

RUN apt-get update && apt-get install -y sudo nano python-pip time git && rm -rf /var/lib/apt/lists/* && apt clean

RUN useradd -m ubuntu && \
 echo ubuntu:ubuntu | chpasswd && \
 cp /etc/sudoers /etc/sudoers.bak && \ 
 echo 'ubuntu  ALL=(root) NOPASSWD: ALL' >> /etc/sudoers

USER ubuntu
WORKDIR /home/ubuntu

COPY fully-symbolic-memory /home/ubuntu/fully-symbolic-memory
COPY CGC /home/ubuntu/CGC

RUN cd /home/ubuntu/fully-symbolic-memory/env-setup && \
 sudo chown ubuntu:ubuntu -R ../ && \
 sudo pip install simuvex==5.6.12.3 angr==5.6.12.3 cle==5.6.12.3 pyvex==5.6.10.5 claripy==5.6.12.3 bitstring namedlist sortedcontainers pympler && \
 sudo pip install --no-index --find-links=/home/ubuntu/fully-symbolic-memory/env-setup/simuvex-5.6.12.3.tgz simuvex && \
 sudo patch /usr/local/lib/python2.7/dist-packages/angr/exploration_techniques/veritesting.py veritesting.patch
