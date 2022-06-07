FROM python:3.10.4-bullseye

RUN sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list
RUN apt-get update

RUN apt-get -y install ruby2.7 ruby2.7-dev && \
gem install wpscan -v 3.8.22

COPY ./keyword.txt  /usr/