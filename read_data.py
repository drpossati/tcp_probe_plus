#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import os
import sys
import datetime
import logging
import shutil

def ipaddr_ntos(ipaddr):
    return "%d.%d.%d.%d" % (
            (ipaddr >> 24) & 0xff,
            (ipaddr >> 16) & 0xff,
            (ipaddr >> 8) & 0xff,
            (ipaddr) & 0xff,
    )

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

    def parse_line(self, line, num_base=16):
        """ Parse a line into dictionary.

        line: A string containing line to be parsed
        num_base: Base of all numbers

        Returns:
            A dictionary containing the data
        """
        result = {}
        line = line.split()
        result = {}
        result["type"] = int(line[0], base=num_base)
        result["timestamp"] = (int(line[1], base=num_base) +
                int(line[2], base=num_base) / 1000 / 1000.0 / 1000.0)
        result["srcaddr"] = int(line[3], base=num_base)
        result["srcport"] = int(line[4], base=num_base)
        result["dstaddr"] = int(line[5], base=num_base)
        result["dstport"] = int(line[6], base=num_base)
        result["length"] = int(line[7], base=num_base)
        result["tcp_flags"] = int(line[8], base=num_base)
        result["seq_num"] = int(line[9], base=num_base)
        result["ack_num"] = int(line[10], base=num_base)
        result["ca_state"] = int(line[11], base=num_base)
        result["snd_nxt"] = long(line[12], base=num_base)
        result["snd_una"] = int(line[13], base=num_base)
        result["write_seq"] = int(line[14], base=num_base)
        result["wqueue"] = int(line[15], base=num_base)
        result["snd_cwnd"] = int(line[16], base=num_base)
        result["ssthreshold"] = int(line[17], base=num_base)
        result["snd_wnd"] = int(line[18], base=num_base)
        result["srtt"] = int(line[19], base=num_base)
        result["mdev"] = int(line[20], base=num_base)
        result["rttvar"] = int(line[21], base=num_base)
        result["rto"] = int(line[22], base=num_base)
        result["packets_out"] = int(line[23], base=num_base)
        result["lost_out"] = int(line[24], base=num_base)
        result["sacked_out"] = int(line[25], base=num_base)
        result["retrans_out"] = int(line[26], base=num_base)
        result["retrans"] = int(line[27], base=num_base)
        result["frto_counter"] = int(line[28], base=num_base)
        result["rto_num"] = int(line[29], base=num_base)
        result["user-agent"] = ""
        if len(line) >= 31:
            result["user-agent"] =  " ".join(line[30:])
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
                    line["srcaddr"] = ipaddr_ntos(line["srcaddr"])
                    line["dstaddr"] = ipaddr_ntos(line["dstaddr"])
                    oline = ""
                    for fmt_str, keyname in keys:
                        oline += " "
                        oline += fmt_str % line[keyname]
                    ofp.write(oline + "\n")
                    ofp.flush()


    def read_and_store(self, file_size_max = (1 << 30), flush_max = 30):
        """ just read data and store it into file
        Args:
            file_size_max: A number contaning the maximum bytes of a file. When
                the log file size is larger than file_size_max, a new file will
                be created.
            flush_max: A number representing the maximum number of flush lines.
                when # of lines in buffer are larger than flush_max, all lines
                will be flushed into disk.
        """
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
