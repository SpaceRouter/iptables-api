FROM golang:rc-alpine

<<<<<<< HEAD
ENV APP_NAME iptables_api
=======
LABEL "space.opengate.vendor"="SpaceRouter"
LABEL org.opencontainers.image.source https://github.com/SpaceRouter/iptables-api
LABEL space.opengate.image.authors="theo.lefevre@edu.esiee.fr"

ENV APP_NAME iptables-api
>>>>>>> ee9e5924e9dd07b642e5030cdf850497ccb2eeae

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
