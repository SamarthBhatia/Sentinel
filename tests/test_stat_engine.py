from statistical_anomaly_detector import StatisticalAnomalyEngine
def test_detect_spike():
    eng=StatisticalAnomalyEngine({'sensitivity':2.0})
    alerts=[]
    for i in range(120):
        val=1000 if i==60 else 100
        alerts+=eng.add_observation(i,{'packet_rate':val,'bandwidth_usage':val*1000})
    assert any(a.severity in ('high','critical') for a in alerts)
