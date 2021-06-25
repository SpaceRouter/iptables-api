FROM golang:rc-alpine

LABEL "space.opengate.vendor"="SpaceRouter"
LABEL org.opencontainers.image.source https://github.com/SpaceRouter/iptables-api
LABEL space.opengate.image.authors="theo.lefevre@edu.esiee.fr"

ENV APP_NAME iptables-api

COPY src /source
WORKDIR /source

RUN apk add gcc

RUN go get && \
 go build -o /usr/bin/$APP_NAME && \
 rm -rf $GOPATH/pkg/

RUN mkdir /config && cp config/*.yaml /config -r

WORKDIR /

ENV GIN_MODE=release

VOLUME /etc/sr/

CMD $APP_NAME
