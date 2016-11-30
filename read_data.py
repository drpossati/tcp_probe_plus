#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys


def read_and_store(ifp, ofp):
    while True:
        line = ifp.readline()
        if not line:
            break
        print line.split()


def main():
    ifname = "/proc/net/tcpprobe_data"
    with open(ifname) as ifp:
        read_and_store(ifp, sys.stdout)

if __name__ == "__main__":
    main()
