import logging
import ptf
# import ptf.packet as scapy

from scapy.all import fuzz, RandIP, RandIP6
from ptf.base_tests import BaseTest
from ptf.testutils import *


class IpFuzzTest(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)

    def log(self, message):
        logging.info(message)

    def setUp(self):
        BaseTest.setUp(self)
        self.dataplane = ptf.dataplane_instance
        self.test_params = test_params_get()
        self.dataplane.flush()
        self.log("IP Fuzz test setup")

    def tearDown(self):
        self.log("IP fuzz test teardown")

    @staticmethod
    def generate_ip_address(ip_version):
        if ip_version == 4:
            return RandIP()
        else:
            return RandIP6()

    def build_fuzz_ip_packet(self, src_ip, dest_ip, ip_version):
        assert(ip_version in [4, 6])
        if src_ip is None:
            src_ip = self.generate_ip_address(ip_version)
        if dest_ip is None:
            dest_ip = self.generate_ip_address(ip_version)
        return fuzz(scapy.IP(src=src_ip, dst=dest_ip))

    def build_fuzz_tcp_packet(self, src_ip=None, dest_ip=None, ip_version=4):
        assert(ip_version in [4, 6])
        if src_ip is None:
            src_ip = self.generate_ip_address(ip_version)
        if dest_ip is None:
            dest_ip = self.generate_ip_address(ip_version)
        return fuzz(scapy.IP(src=src_ip, dst=dest_ip)/scapy.TCP())

    def build_fuzz_udp_packet(self, src_ip=None, dest_ip=None, ip_version=4):
        assert(ip_version in [4, 6])
        if src_ip is None:
            src_ip = self.generate_ip_address(ip_version)
        if dest_ip is None:
            dest_ip = self.generate_ip_address(ip_version)
        return fuzz(scapy.IP(src=src_ip, dst=dest_ip)/scapy.UDP())

    def check_param(self, param, default, required):
        if param not in self.test_params:
            if required:
                raise Exception("Test parameter '%s' is required" % param)
            self.test_params[param] = default

    def runTest(self):

        # I need to know
        #  What type of packets to generate
        #  optionally a packet count
        #  which switch port to send traffic to
        #  optionally the source and destination IP addresses

        self.check_param('port', '', required=True)
        self.check_param('packet_type', 'ip', required=False)
        self.check_param('packet_count', 1, required=False)
        self.check_param('src_ip', None, required=False)
        self.check_param('dest_ip', None, required=False)
        self.check_param('ip_version', 4, required=False)

        if self.test_params['packet_type'] == 'ip':
            pkt = self.build_fuzz_ip_packet(
                src_ip=self.test_params['src_ip'],
                dest_ip=self.test_params['dest_ip'],
                ip_version=self.test_params['ip_version'])
        elif self.test_params['packet_type'] == 'tcp':
            pkt = self.build_fuzz_tcp_packet()
        elif self.test_params['packet_type'] == 'udp':
            pkt = self.build_fuzz_udp_packet()
        else:
            raise ValueError('Unknown packet type: ' + self.test_params['packet_type'])

        self.log("Sending test packet(s)")
        send(self, self.test_params['port'], pkt)

