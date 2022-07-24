#!/usr/bin/env bash

sudo ip tuntap add user tim mode tun tun_tcp
sudo ip link set tun_tcp up
sudo ip addr add 10.0.0.1/24 dev tun_tcp

go build
./tcp