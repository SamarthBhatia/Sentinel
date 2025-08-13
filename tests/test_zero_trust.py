import time, zero_trust_engine as zt
cfg={'normal_packet_rate':1000,'normal_bandwidth':1e7,'max_destinations':50}
def test_blocking():
    z=zt.ZeroTrustEngine(cfg)
    ctx={'behavior':{'packet_rate':500,'bandwidth_usage':1e6,
                     'connection_patterns':{'destinations':['1.1.1.1']}},
         'authentication':{'mfa_verified':True}}
    assert z.evaluate_entity('10.0.0.1',zt.EntityType.DEVICE,ctx)[0] >= zt.TrustLevel.HIGH
    ctx['behavior']['packet_rate']=5000
    assert z.evaluate_entity('10.0.0.1',zt.EntityType.DEVICE,ctx) == zt.TrustLevel.UNTRUSTED
