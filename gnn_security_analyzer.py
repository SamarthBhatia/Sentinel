#!/usr/bin/env python3
"""
GNN-based intrusion detector (GraphSAGE w/ torch-geometric fallback)
"""
import torch, torch.nn as nn, torch.nn.functional as F, time, logging, random
from dataclasses import dataclass
from typing import List, Dict
try:
    from torch_geometric.nn import GraphSAGE
    from torch_geometric.data import Data
    GEOM=True
except ImportError:
    GEOM=False
    print("⚠ torch_geometric not found – switching to dense fallback")

@dataclass
class NetworkFlow:
    src_ip:str; dst_ip:str; src_port:int; dst_port:int; protocol:str
    packet_size:int; duration:float; flags:int; ttl:int; timestamp:float
    is_attack:bool=False

# ---------- builder ----------
class GraphBuilder:
    def __init__(self): self.ip2idx={}; self.idx2ip={}
    def encode_proto(self,p): return {'TCP':1,'UDP':2,'ICMP':3}.get(p,0)
    def build(self,flows:List[NetworkFlow]):
        ips=set(); [ips.update((f.src_ip,f.dst_ip)) for f in flows]
        self.ip2idx={ip:i for i,ip in enumerate(sorted(ips))}
        edges=[]; eattr=[]; elabel=[]
        for f in flows:
            s=self.ip2idx[f.src_ip]; d=self.ip2idx[f.dst_ip]
            edges.append([s,d])
            eattr.append([f.packet_size,f.duration,self.encode_proto(f.protocol),
                          f.flags,f.ttl])
            elabel.append(1 if f.is_attack else 0)
        nfeat=[[0] for _ in self.ip2idx]  # trivial node feature
        if GEOM:
            return Data(x=torch.tensor(nfeat,dtype=torch.float),
                        edge_index=torch.tensor(edges).t(),
                        edge_attr=torch.tensor(eattr,dtype=torch.float),
                        edge_labels=torch.tensor(elabel))
        return {"node":nfeat,"edge":edges,"eattr":eattr,"elabel":elabel}

# ---------- models ----------
class DenseGNN(nn.Module):            # fallback
    def __init__(self, nedgefeat): super().__init__()
    def forward(self,data): ...

if GEOM:
    class SageModel(nn.Module):
        def __init__(self,nedgefeat,h=64):
            super().__init__()
            self.sage1=GraphSAGE(1,h,2)
            self.sage2=GraphSAGE(h,h,2)
            self.cls=nn.Sequential(nn.Linear(h*2+nedgefeat,h),
                                   nn.ReLU(),nn.Linear(h,2))
        def forward(self,d):
            emb=F.relu(self.sage1(d.x,d.edge_index))
            emb=F.relu(self.sage2(emb,d.edge_index))
            src=emb[d.edge_index[0]]; dst=emb[d.edge_index[1]]
            logits=self.cls(torch.cat([src,dst,d.edge_attr],1))
            return logits
else:
    SageModel=DenseGNN

# ---------- high-level wrapper ----------
class GNNSecurityAnalyzer:
    def __init__(self,cfg:Dict):
        self.cfg=cfg; self.bld=GraphBuilder()
        self.device=torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model=None; self.log=logging.getLogger("GNN")

    def train_model(self,flows:List[NetworkFlow]):
        data=self.bld.build(flows); nedgefeat=len(data.edge_attr[0]) if GEOM else len(data["eattr"])
        self.model=SageModel(nedgefeat,self.cfg.get("hidden",64)).to(self.device)
        opt=torch.optim.Adam(self.model.parameters(),lr=1e-3)
        y=data.edge_labels.to(self.device) if GEOM else torch.tensor(data["elabel"])
        for epoch in range(self.cfg.get("epochs",20)):
            self.model.train(); opt.zero_grad()
            out=self.model(data.to(self.device) if GEOM else data)
            loss=F.cross_entropy(out,y)
            loss.backward(); opt.step()
            if epoch%5==0: self.log.info("epoch %d loss %.4f",epoch,loss)

    def predict(self,flows:List[NetworkFlow])->float:
        if not self.model: raise RuntimeError("train first")
        data=self.bld.build(flows)
        self.model.eval()
        with torch.no_grad():
            logits=self.model(data.to(self.device) if GEOM else data)
            prob=F.softmax(logits,1)[:,1].mean().item()
        return prob
