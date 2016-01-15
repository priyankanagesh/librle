#!/usr/bin/env python2.7
#-*- coding: utf-8 -*-

"""
------------------------------------------------------------------------------
About
==============================================================================
GEN RAND IPv4 TRACE

Generate a trace containing random len IPv4 packets.

To improve:
 - Numerous error cases not explicitly passed.
 - Non-pythonic way to simplify the script.
------------------------------------------------------------------------------
"""

SCRIPT_NAME = r"""
   +-----------------------+
   |  Gen rand IPv4 trace  |
   +-----------------------+
"""

__author__ = "Henrick Deschamps"
__copyright__ = "Copyright 2016, Thalès Alenia Space"
__credits__ = ["Henrick Deschamps"]
__license__ = "Copyright"
__version__ = "0.1"
__maintainer__ = "Henrick Deschamps"
__email__ = "henrick.deschamps@toulouse.viveris.com"
__status__ = "Conception"

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from sys import argv
from sys import exit as sys_exit
from getopt import getopt
from getopt import GetoptError
from string import digits
from string import ascii_uppercase
from string import ascii_lowercase
from scapy.layers.l2 import Ether
from scapy.layers.l2 import Raw
from scapy.layers.inet import IP
from scapy.sendrecv import sendp
from random import normalvariate


PAYLOAD_SEED = digits + ascii_uppercase + ascii_lowercase
DEFAULT_NUMBER_OF_PACKETS = 1
DEFAULT_DUMP_FILENAME = "dummy0"
DEFAULT_MIN_PAYLOAD_LEN = 64
DEFAULT_MAX_PAYLOAD_LEN = 1486
DEFAULT_AVG_PAYLOAD_LEN = 450
DEFAULT_STD_DEV_PAYLOAD_LEN = 300


class PayloadLength(object):

    """ Paylaod length generator """

    def __init__(self, min_len, max_len, avg_len, std_dev):
        """ Paylaod length generator constructor

        in:
            min_len: minimum length of the paylaod.
            max_len: minimum length of the paylaod.
            avg_len: mu (normal distribution).
            std_dev: sigma (normal distribution).

        """
        self.__min_len = min_len
        self.__max_len = max_len
        self.__avg_len = avg_len
        self.__std_dev = std_dev

    def rand_payload_len(self):
        """ Function random payload length.

        Return a random payload length (normal distribution).

        out:
            payload_len: The payload length.
        """
        payload_len = int(normalvariate(self.__avg_len, self.__std_dev))
        payload_len = max([self.__min_len, payload_len])
        payload_len = min([self.__max_len, payload_len])
        return payload_len

    def to_string(self):
        """ To string function.

        Return a stringify version of the object.

        out:
            stringify: the stringify version of the object.
        """
        stringify = ""

        stringify += "Average len: " + str(self.__avg_len) + ", "
        stringify += "Std dev: " + str(self.__std_dev) + ", "
        stringify += "Min len: " + str(self.__min_len) + ", "
        stringify += "Max len: " + str(self.__max_len)

        return stringify


def padding_generator(seed, length):
    """ Function padding generator.

    Generate padding from a seed and a length. Based on an affine approach.

    in:
        seed:       The seed of the padding.
        length:     The size of the padding.

    out:
        padding:    The generated padding.
    """
    homothecy = length / len(seed)
    translation = seed[:length - (len(seed) * homothecy)]
    padding = (homothecy * seed) + translation
    return padding


def make_payload(seed, length, headers_offset):
    """ Function make payload.

    Make a payload for a packet.

    in:
        number:     The id of the payload.
        seed:       The seed of the padding in the payload.
        length:     The length of the padding in the payload.
        offset:     An offset to considerate, like headers sizes.

    out:
        payload:    The payload generated.
    """
    payload = padding_generator(seed, length - headers_offset)
    return payload


def send_frames(payload_len, dump_size, dump_filename):
    """ Send frames function

    send the frames.

    """
    for int_iterator in range(dump_size):
        l2_header = Ether(src="00:11:22:33:44:55", dst="55:44:33:22:11")
        l3_header = IP(src="192.168.1.1", dst="192.168.1.2", id=int_iterator)
        payload = Raw(make_payload(
            PAYLOAD_SEED,
            payload_len.rand_payload_len(),
            len(l3_header)))
        pkt = l2_header / l3_header / payload
        sendp(pkt, iface=dump_filename, verbose=False)
        if int_iterator % 100 == 0:
            print "... " + str(int_iterator) + " packets sent..."


def usage():
    """ Usage function

    Print the usage of this script.

    """
    print SCRIPT_NAME
    print "Send packets."
    print ""
    print "Options:"
    print "\t-m, --mu:       average size of the payload (default 450)"
    print "\t-s, --sigma:    std dev of the payload (default 300)"
    print "\t-l, --min_len:  min size of the payload (default 64)"
    print "\t-u, --max_len:  max size of the payload (default 1486)"
    print "\t-n, --size:     number of packets in the dump (default 1)"
    print "\t-o, --output:   output interface (default dummy0)"
    print "\t-h, --help:     display this message"
    print ""


def parse_arguments():
    """ Parse arguments function

    Parse the arguments from the command line

    """
    # Default arguments:
    dump_size = DEFAULT_NUMBER_OF_PACKETS
    dump_filename = DEFAULT_DUMP_FILENAME
    avg_payload_len = DEFAULT_AVG_PAYLOAD_LEN
    std_dev_payload_len = DEFAULT_STD_DEV_PAYLOAD_LEN
    min_payload_len = DEFAULT_MIN_PAYLOAD_LEN
    max_payload_len = DEFAULT_MAX_PAYLOAD_LEN

    getopt_options = "hn:o:p:m:s:l:u:"
    getopt_long_options = ["mu=", "sigma=", "min_len=", "max_len=", "size=",
                           "output=", "help"]

    try:
        opts, args = getopt(argv[1:], getopt_options, getopt_long_options)
        del args
    except GetoptError as err:
        usage()
        print str(err)
        sys_exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys_exit()
        elif opt in ("-m", "--mu"):
            if not arg.isdigit():
                usage()
                sys_exit(2)
            avg_payload_len = int(arg)
        elif opt in ("-s", "--sigma"):
            if not arg.isdigit():
                usage()
                sys_exit(2)
            std_dev_payload_len = int(arg)
        elif opt in ("-l", "--min_payload_len"):
            if not arg.isdigit():
                usage()
                sys_exit(2)
            min_payload_len = int(arg)
        elif opt in ("-u", "--max_payload_len"):
            if not arg.isdigit():
                usage()
                sys_exit(2)
            max_payload_len = int(arg)
        elif opt in ("-n", "--number"):
            if not arg.isdigit():
                usage()
                sys_exit(2)
            dump_size = int(arg)
        elif opt in ("-o", "--output"):
            dump_filename = arg
        else:
            usage()
            assert False, "unhandled option"
            sys_exit(2)

    payload_len = PayloadLength(min_payload_len, max_payload_len,
                                avg_payload_len, std_dev_payload_len)

    return payload_len, dump_size, dump_filename


def main():
    """ Main function """

    payload_len, dump_size, dump_filename = parse_arguments()

    print SCRIPT_NAME

    print "Payload length = " + payload_len.to_string()
    print "Output = " + dump_filename
    print "Sending..."

    send_frames(payload_len, dump_size, dump_filename)

    print "End. " + str(dump_size) + " packets sent."
    print ""


if __name__ == "__main__":
    main()
