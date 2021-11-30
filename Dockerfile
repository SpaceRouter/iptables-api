FROM golang:rc-alpine

ENV APP_NAME iptables_api

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
