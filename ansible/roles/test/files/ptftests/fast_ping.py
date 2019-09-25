'''
Description:    Sends ICMP echo packets to a route destination IP and verifies forwarding

Usage:          Examples of how to start this script
                ptf --test-dir ptftests fast_ping.FastPingTest --platform-dir ptftests --platform remote -t \"router_mac='00:e0:ec:89:4e:0b';src_ip='10.0.0.35';dest_ip='100.1.0.19';send_port=5;recv_port=6;duration_seconds=15;packet_interval_ms=10\"  --relax --debug info --log-file /tmp/fast_ping.FastPingTest.log
'''

import logging
import ptf
import ptf.packet as scapy
import ptf.dataplane as dataplane

from ptf import config
from ptf.base_tests import BaseTest
from ptf.mask import Mask
from ptf.testutils import *
import time


class FastPingTest(BaseTest):
    """"""

    def __init__(self):
        BaseTest.__init__(self)
        self.test_params = test_params_get()

    def check_param(self, param, default, required=False):
        if param not in self.test_params:
            if required:
                raise Exception("Test parameter '%s' is required" % param)
            self.test_params[param] = default

    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        self.check_param('router_mac', False, required=True)
        self.check_param('src_ip', False, required=True)
        self.check_param('send_port', False, required=True)
        self.check_param('dest_ip', False, required=True)
        self.check_param('recv_port', False, required=True)
        self.check_param('duration_seconds', 10, required=False)
        self.check_param('packet_interval_ms', 10, required=False)

        self.router_mac = self.test_params['router_mac']
        self.src_ip = self.test_params['src_ip']
        self.dest_ip = self.test_params['dest_ip']
        self.send_port = self.test_params['send_port']
        self.recv_port = self.test_params['recv_port']
        self.duration_seconds = self.test_params['duration_seconds']
        self.packet_interval_ms = self.test_params['packet_interval_ms']

    def check_icmp(self):
        """Check ICMP/Ping to a next hop forwarded by the DUT"""
        src_mac = self.dataplane.get_mac(0, self.send_port)
        recv_mac = self.dataplane.get_mac(0, self.recv_port)

        pkt = simple_icmp_packet(eth_dst=self.router_mac,
                                 eth_src=src_mac,
                                 ip_src=self.src_ip,
                                 ip_dst=self.dest_ip)

        # We expect the original packet to be forwarded to another port that
        # is the next hop of the route we are testing.
        exp_pkt = simple_icmp_packet(eth_dst=recv_mac,
                                     eth_src=self.router_mac,
                                     ip_src=self.src_ip,
                                     ip_dst=self.dest_ip)

        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "id")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")  # TODO: comment out?
        masked_exp_pkt.set_do_not_care_scapy(scapy.ICMP, "chksum")

        logging.info("Sending ICMP packets with src_ip {}, dest_ip {}".format(
            self.src_ip, self.dest_ip))

        # Repeat this test for a given number of seconds
        t_end = time.time() + self.duration_seconds
        count = 0
        while time.time() < t_end:
            logging.info("Send packet {} from port {}".format(count, self.send_port))
            send_packet(self, self.send_port, pkt)
            verify_packet(self, masked_exp_pkt, self.recv_port)
            logging.info("Received packet {} on port {}".format(count, self.recv_port))
            time.sleep(0.001 * self.packet_interval_ms)
            count += 1
        return

    def runTest(self):
        self.check_icmp()
