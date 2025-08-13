from gnn_security_analyzer import GNNSecurityAnalyzer, NetworkFlow
def test_gnn_train_predict():
    flows=[NetworkFlow('a','b',1234,80,'TCP',500,0,0,64,0,False) for _ in range(40)]
    flows+= [NetworkFlow('a','b',1234,80,'TCP',1500,0,2,64,0,True) for _ in range(10)]
    g=GNNSecurityAnalyzer({'epochs':5,'hidden':16})
    g.train_model(flows)
    assert 0 <= g.predict(flows[:10]) <= 1
