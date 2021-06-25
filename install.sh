#!/bin/sh

cd src
go build -o /usr/bin/iptables-api
cp iptables-api.service /etc/systemd/user/
systemctl enable iptables-api
systemctl start iptables-api
