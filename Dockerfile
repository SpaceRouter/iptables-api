
FROM golang

COPY src /source
WORKDIR /source

RUN go get
RUN go build -o /usr/bin/iptables_api

RUN mkdir /config && cp config/*.yaml /config -r

WORKDIR /

ENV GIN_MODE=release

CMD iptables_api