#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import os
import sys
import datetime
import logging
import shutil


class tcp_log_reader(object):
    """ Read tcp log from file

    Attributes:
        ifname: A string representing the input file containing tcp logs
        odir: A string representing the directory to put tcp log in
        oname: A string representing the file name to put tcp log in
        archive_dir: A string representing the archive directory hosting
            history tcp logs
    """
    def __init__(self, ifname, odir="output", oname="tcp-stat.log"):
        self.ifname = ifname
        self.odir = odir
        self.archive_dir = "archive"
        self.oname = oname
        self.check_trace_dir()

    def check_trace_dir(self):
        """ Check whether trace directory exists. If so, move it the archive directory
        """
        if os.path.exists(self.odir) and os.listdir(self.odir):
            logging.error("'%s' exists!" % self.odir)
            timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            dst_file = "%s/%s_%s" % (self.archive_dir, self.odir, timestamp)
            logging.info("Copy '%s' to '%s'" % (self.odir, dst_file))
            if not os.path.exists(self.archive_dir):
                os.mkdir(self.archive_dir)
            shutil.move(self.odir, dst_file)
            os.mkdir(self.odir)
        elif not os.path.exists(self.odir):
            os.mkdir(self.odir)

    def read_and_print(self):
        """ Read data and print on screen
        """
        with open(self.ifname) as ifp:
            while True:
                line = ifp.readline()
                if not line:
                    break
                print line

    def parse_line(self, line):
        """ Parse a line into dictionary.

        Returns:
            A dictionary containing the data
        """
        result = {}
        line = line.split()
        result = {
            "type": int(line[0]),
            "timestamp": float(line[1]),
            "srcaddr": line[2].split(":")[0],
            "srcport": int(line[2].split(":")[1]),
            "dstaddr": line[3].split(":")[0],
            "dstport": int(line[3].split(":")[1]),
            "length": int(line[4]),
            "flags": int(line[5]),
            "seq_num": int(line[6]),
            "ack_num": int(line[7]),
            "snd_nxt": long(line[8]),
            "snd_una": int(line[9]),
            "cwnd": int(line[10]),
            "ssthreshold": int(line[11]),
            "recv_wnd": int(line[12]),
            "srtt": int(line[13]),
            "rttvar": int(line[14]),
            "rtt_mdev": int(line[15]),
            "rto": int(line[16]),
            "lost_out": int(line[17]),
            "retrans_num": int(line[18]),
            "inflight": int(line[19]),
            "frto_counter": int(line[20]),
            "rto_num": int(line[21]),
            "recv_buff": int(line[22]),
            "send_buff": int(line[23]),
        }
        result["user-agent"] = ""
        if len(line) >= 25:
            result["user-agent"] =  " ".join(line[24:])
        return result

    def read_parse_and_store(self):
        """ Read data, parse information, and store it into output file
        """
        ofname = os.path.join(self.odir, self.oname)
        with open(self.ifname) as ifp:
            with open(ofname, "w") as ofp:
                while True:
                    line = ifp.readline()
                    if not line:
                        break
                    line = self.parse_line(line)
                    oline = "%d %.6f %s:%d %d %#x" % (
                        line["type"], line["timestamp"],
                        line["dstaddr"], line["dstport"],
                        line["length"], line["flags"],
                    )
                    oline = "%s %d %d %ld %d" % (
                        oline, line["seq_num"], line["ack_num"],
                        line["snd_nxt"], line["snd_una"]
                    )
                    oline = "%s %d %d %d" % (
                        oline, line["cwnd"],
                        line["ssthreshold"], line["recv_wnd"]
                    )
                    oline = "%s %d %d %d %d" % (
                        oline, line["srtt"], line["rto"],
                        line["rto_num"], line["frto_counter"]
                    )
                    oline = "%s %d %d %d" % (
                        oline, line["inflight"],
                        line["lost_out"], line["retrans_num"]
                    )
                    oline = "%s %d %s" % (
                        oline, line["send_buff"], line["user-agent"]
                    )
                    ofp.write(oline + "\n")
                    ofp.flush()

    def read_parse_select_and_store(self, *keys):
        """ Read data, parse information, and store it into output file
        Args:
            keys: A list of tuples containing format string and key names to store into file:
                (<format str>, <keyname>)
        """
        ofname = os.path.join(self.odir, self.oname)
        with open(self.ifname) as ifp:
            with open(ofname, "w") as ofp:
                while True:
                    line = ifp.readline()
                    if not line:
                        break
                    line = self.parse_line(line)
                    oline = ""
                    for fmt_str, keyname in keys:
                        oline += " "
                        oline += fmt_str % line[keyname]
                    ofp.write(oline + "\n")
                    ofp.flush()


    def read_and_store(self):
        """ just read data and store it into file
        """
        flush_max = 30
        file_size_max = 1 * 1024 * 1024 * 1024
        file_num = 1
        with open(self.ifname) as ifp:
            try:
                while True:
                    ofname = self.oname + (".%d" % file_num)
                    ofname = os.path.join(self.odir, ofname)
                    ofp = open(ofname, "w")
                    flush_num, file_size = 0, 0
                    while True:
                        line = ifp.readline()
                        if not line:
                            break
                        ofp.write(line)
                        file_size += len(line)
                        flush_num += 1
                        if flush_num > flush_max:
                            ofp.flush()
                            flush_num = 0
                        if file_size > file_size_max:
                            break
                    ofp.close()
                    if not line:
                        break
                    file_num += 1
            except KeyboardInterrupt:
                logging.warning("Receive Interrupt Signal\n")
            finally:
                if not ofp.closed:
                    ofp.close()


def main():
    ifname = "/proc/net/tcpprobe_data"
    reader = tcp_log_reader(ifname)
    reader.read_and_store()

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)-5s %(levelname)-6s %(message)s "
        "(in %(filename)s function '%(funcName)s' line %(lineno)s)",
        datefmt="%m-%d %H:%M",
    )
    main()
