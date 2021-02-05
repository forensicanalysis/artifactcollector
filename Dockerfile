FROM golang:1.15.8

RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys AA8E81B4331F7F50
RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 9D6D8F6BC857C906
RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 7638D0442B90D010
RUN apt update
RUN apt install -y mingw-w64

ENV GOOS=windows
ENV GOARCH=386
ENV CC=gcc

RUN cd /usr/src/go/src && bash make.bash

ENV CGO_ENABLED=1
ENV CC=i686-w64-mingw32-gcc
