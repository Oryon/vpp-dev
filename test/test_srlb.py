import socket

from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, GRE
from scapy.packet import Raw

from framework import VppTestCase, VppTestRunner
from util import Host, ppp
from vpp_srlb import VppSRLBVIP, SRLBLBHash, VppSRLBConf, VppSRLBServer, VppSRLBAgentConf

from socket import inet_pton, inet_ntop, AF_INET, AF_INET6


class TestSRLB(VppTestCase):
    """ SRv6 Load Balancer Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestSRLB, cls).setUpClass()
    
    def tearDown(self):
        super(TestSRLB, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show srlb lb vip"))
    
    
    def test_lb_conf_api(self):
        """ Test basic SRLB LB conf API calls.
        """
        
        # Some global configuration testing
        conf = VppSRLBConf(self)
        conf.get_conf()
        
        self.assertEqual(conf.flow_active_timeout, 40)
        self.assertEqual(conf.flow_teardown_timeout, 2)
        self.assertEqual(conf.flowhash_fixed_entries, 1024)
        self.assertEqual(conf.flowhash_collision_buckets, 256)
        
        conf.flow_active_timeout = 30
        conf.set_conf()
        conf.flow_active_timeout = 40 # To make sure we dont read the old value
        conf.get_conf()
        self.assertEqual(conf.flow_active_timeout, 30)
        
        conf.flow_teardown_timeout = 4
        conf.flowhash_fixed_entries = 23456
        conf.flowhash_collision_buckets = 123
        conf.set_conf()
        conf.get_conf()
        self.assertEqual(conf.flow_active_timeout, 30)
        self.assertEqual(conf.flow_teardown_timeout, 4)
        self.assertEqual(conf.flowhash_fixed_entries, 32768)
        self.assertEqual(conf.flowhash_collision_buckets, 128)
        
    def test_lb_api(self):
        """ Test various SRLB LB API returns.
        """
        
        vip = VppSRLBVIP(self, vip_prefix="2001:1::", vip_prefix_length=64,
                        sr_prefix="2001:2::", sr_prefix_length=80, 
                        client_rx_vrf_id=0, client_tx_vrf_id=0,
                        consistent_hashtable_size=1024,
                        sr_rx_vrf_id=0, sr_tx_vrf_id=0,
                        hash_type=SRLBLBHash.SRLB_LB_HASH_5_TUPLE);
        
        # Testing some failure cases
        vip.sr_prefix_length = 90
        vip.add_vpp_config(expected_retval=-73)
        vip.sr_prefix_length = 80
        
        vip.client_rx_vrf_id = 1
        vip.add_vpp_config(expected_retval=-3)
        vip.client_rx_vrf_id = 0
        
        vip.client_tx_vrf_id = 1
        vip.add_vpp_config(expected_retval=-3)
        vip.client_tx_vrf_id = 0
        
        vip.sr_rx_vrf_id = 1
        vip.add_vpp_config(expected_retval=-3)
        vip.sr_rx_vrf_id = 0
        
        vip.sr_tx_vrf_id = 1
        vip.add_vpp_config(expected_retval=-3)
        vip.sr_tx_vrf_id = 0
        
        # Create and delete
        vip.add_vpp_config()
        vip.remove_vpp_config()
        vip.add_vpp_config()
        vip.remove_vpp_config()
        
        # Let's configure some servers now
        vip = VppSRLBVIP(self, vip_prefix="2001:1::", vip_prefix_length=64,
                        sr_prefix="2001:2::", sr_prefix_length=80, 
                        client_rx_vrf_id=0, client_tx_vrf_id=0,
                        consistent_hashtable_size=1024,
                        sr_rx_vrf_id=0, sr_tx_vrf_id=0,
                        hash_type=SRLBLBHash.SRLB_LB_HASH_5_TUPLE);
        vip.add_vpp_config();
        
        servers = [VppSRLBServer.create_server("2001:2::", 80),
                   VppSRLBServer.create_server("2001:3::", 80)]
        s = VppSRLBServer(self, vip, 3, servers)
        s.add_vpp_config()
        s.remove_vpp_config()
        
        
        servers = [VppSRLBServer.create_server("2001:2::", 81)]
        s = VppSRLBServer(self, vip, 3, servers)
        s.add_vpp_config(expected_retval=-73)
        
        vip.remove_vpp_config();
        
        # Try to add on a vip that does not exist
        servers = [VppSRLBServer.create_server("2001:2::", 80)]
        s = VppSRLBServer(self, vip, 3, servers)
        s.add_vpp_config(expected_retval=-6)
        
        vip.add_vpp_config()
        s.add_vpp_config()
        vip.remove_vpp_config()
        
        return 0
    
    
    def test_sa_conf_api(self):
        """ Test basic SRLB SA conf API calls.
        """
        
        # Doing some basic configuration tests
        conf = VppSRLBAgentConf(self)
        conf.get_conf()
        
        self.assertEqual(conf.flow_active_timeout, 40)
        self.assertEqual(conf.flow_teardown_timeout, 2)
        self.assertEqual(conf.flowhash_fixed_entries, 1024)
        self.assertEqual(conf.flowhash_collision_buckets, 256)
        
        conf.flow_active_timeout = 30
        conf.set_conf()
        conf.flow_active_timeout = 40 # To make sure we dont read the old value
        conf.get_conf()
        self.assertEqual(conf.flow_active_timeout, 30)
        
        conf.flow_teardown_timeout = 4
        conf.flowhash_fixed_entries = 23456
        conf.flowhash_collision_buckets = 123
        conf.set_conf()
        conf.get_conf()
        self.assertEqual(conf.flow_active_timeout, 30)
        self.assertEqual(conf.flow_teardown_timeout, 4)
        self.assertEqual(conf.flowhash_fixed_entries, 32768)
        self.assertEqual(conf.flowhash_collision_buckets, 128)
        
        return 0
    
    def test_sa_app_api(self):
        """ Test SRLB SA app API calls.
        """
        
        return 0