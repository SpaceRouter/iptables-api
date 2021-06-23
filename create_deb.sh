#!/bin/sh

mkdir -p iptables-api/usr/bin/
go build -o iptables-api/usr/bin/iptables-api .

mkdir -p iptables-api/etc/systemd/system
cp ./iptables-api.service iptables-api/etc/systemd/system
