"""
  VPP's SRLB Object Abstraction
"""

from vpp_object import *
from socket import inet_pton, inet_ntop, AF_INET, AF_INET6

class SRLBLBHash():
    # from srlb/srlb_lb.api
    SRLB_LB_HASH_5_TUPLE = 0
    SRLB_LB_HASH_VIP = 1


class VppSRLBVIP(VppObject):
    """
    SRLB LB VIP Object
    """

    def __init__(self, test, vip_prefix, vip_prefix_length, 
                sr_prefix, sr_prefix_length,
                client_rx_vrf_id, client_tx_vrf_id,
                consistent_hashtable_size,
                sr_rx_vrf_id, sr_tx_vrf_id,
                hash_type):
        
        self._test = test
        self.vip_prefix = inet_pton(AF_INET6, vip_prefix)
        self.vip_prefix_length = vip_prefix_length
        self.sr_prefix = inet_pton(AF_INET6, sr_prefix)
        self.sr_prefix_length = sr_prefix_length
        self.client_rx_vrf_id = client_rx_vrf_id
        self.client_tx_vrf_id = client_tx_vrf_id
        self.sr_rx_vrf_id = sr_rx_vrf_id
        self.sr_tx_vrf_id = sr_tx_vrf_id
        self.hash_type = hash_type
        self.consistent_hashtable_size = consistent_hashtable_size
        self._configured = False

    def add_vpp_config(self, expected_retval=0):
        ret = self._test.vapi.api(self._test.vapi.papi.srlb_lb_vip_conf, {
                "vip_address" : self.vip_prefix,
                "vip_prefix_length" : self.vip_prefix_length,
                "sr_prefix" : self.sr_prefix,
                "sr_prefix_length" : self.sr_prefix_length,
                "consistent_hashtable_size" : self.consistent_hashtable_size,
                "client_rx_vrf_id" : self.client_rx_vrf_id,
                "client_tx_vrf_id" : self.client_tx_vrf_id,
                "sr_rx_vrf_id" : self.sr_rx_vrf_id,
                "sr_tx_vrf_id" : self.sr_tx_vrf_id
            }, expected_retval=expected_retval)
        
        if ret.retval == 0:
            self._configured = True

    def remove_vpp_config(self):
        ret = self._test.vapi.api(self._test.vapi.papi.srlb_lb_vip_conf, {
                "vip_address" : self.vip_prefix,
                "vip_prefix_length" : self.vip_prefix_length,
                "sr_prefix" : self.sr_prefix,
                "sr_prefix_length" : self.sr_prefix_length,
                "consistent_hashtable_size" : self.consistent_hashtable_size,
                "client_rx_vrf_id" : self.client_rx_vrf_id,
                "client_tx_vrf_id" : self.client_tx_vrf_id,
                "sr_rx_vrf_id" : self.sr_rx_vrf_id,
                "sr_tx_vrf_id" : self.sr_tx_vrf_id,
                "is_del" : True
            })
        
        if ret.retval == 0:
            self._configured = False

    def query_vpp_config(self):
        return self._configured

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("%s-%d"
                % (inet_ntop(AF_INET6, self.vip_prefix),
                   self.client_rx_vrf_id))



class VppSRLBServer(VppObject):
    """
    SRLB LB Server Object
    """
    
    @staticmethod
    def create_server(prefix, prefix_length):
        return { "server_prefix" : inet_pton(AF_INET6, prefix), 
                "server_prefix_length" : prefix_length }
    
    def __init__(self, test, vip,
                pool_bitmask,
                servers):
        
        self._configured = False
        self._test = test
        self.vip = vip
        self.pool_bitmask = pool_bitmask
        self.servers = servers
    
    def add_vpp_config(self, expected_retval=0):
        ret = self._test.vapi.api(self._test.vapi.papi.srlb_lb_server_add_del, {
                "vip_prefix" : self.vip.vip_prefix,
                "vip_prefix_length" : self.vip.vip_prefix_length,
                "client_rx_vrf_id" : self.vip.client_rx_vrf_id,
                "pool_bitmask" : self.pool_bitmask,
                "count" : len(self.servers),
                "servers" : self.servers
            }, expected_retval=expected_retval)
        
        if ret.retval == 0:
            self._configured = True
            
    def remove_vpp_config(self, expected_retval=0):
        ret = self._test.vapi.api(self._test.vapi.papi.srlb_lb_server_add_del, {
                "vip_prefix" : self.vip.vip_prefix,
                "vip_prefix_length" : self.vip.vip_prefix_length,
                "client_rx_vrf_id" : self.vip.client_rx_vrf_id,
                "pool_bitmask" : self.pool_bitmask,
                "count" : len(self.servers),
                "servers" : self.servers,
                "is_del" : True
            }, expected_retval=expected_retval)
        
        if ret.retval == 0:
            self._configured = False

    def query_vpp_config(self):
        return self._configured

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("%s-servers"
                % (self.vip.object_id()))

class VppSRLBConf():
    """
    SRLB LB Conf Object
    """
    
    def __init__(self, test):
        self._test = test
        self.flow_active_timeout = 0
        self.flow_teardown_timeout = 0
        self.flowhash_fixed_entries = 0
        self.flowhash_collision_buckets = 0
    
    def get_conf(self):
        ret = self._test.vapi.api(self._test.vapi.papi.srlb_lb_get_conf, {})
        self.flow_active_timeout = ret.flow_active_timeout
        self.flow_teardown_timeout = ret.flow_teardown_timeout
        self.flowhash_fixed_entries = ret.flowhash_fixed_entries
        self.flowhash_collision_buckets = ret.flowhash_collision_buckets
        return ret
    
    def set_conf(self):
        return self._test.vapi.api(self._test.vapi.papi.srlb_lb_conf, {
                "flow_active_timeout" : self.flow_active_timeout,
                "flow_teardown_timeout" : self.flow_teardown_timeout,
                "flowhash_fixed_entries" : self.flowhash_fixed_entries,
                "flowhash_collision_buckets" : self.flowhash_collision_buckets,
            })
    



class VppSRLBAgentConf():
    """
    SRLB SA Conf Object
    """
    
    def __init__(self, test):
        self._test = test
        self.flow_active_timeout = 0
        self.flow_teardown_timeout = 0
        self.flowhash_fixed_entries = 0
        self.flowhash_collision_buckets = 0
    
    def get_conf(self):
        ret = self._test.vapi.api(self._test.vapi.papi.srlb_sa_get_conf, {})
        self.flow_active_timeout = ret.flow_active_timeout
        self.flow_teardown_timeout = ret.flow_teardown_timeout
        self.flowhash_fixed_entries = ret.flowhash_fixed_entries
        self.flowhash_collision_buckets = ret.flowhash_collision_buckets
        return ret
    
    def set_conf(self):
        return self._test.vapi.api(self._test.vapi.papi.srlb_sa_conf, {
                "flow_active_timeout" : self.flow_active_timeout,
                "flow_teardown_timeout" : self.flow_teardown_timeout,
                "flowhash_fixed_entries" : self.flowhash_fixed_entries,
                "flowhash_collision_buckets" : self.flowhash_collision_buckets,
            })