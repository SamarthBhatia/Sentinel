#!/usr/bin/env python3
"""
Zero-Trust continuous-verification engine (NIST 800-207 inspired)
"""
from __future__ import annotations
import time, logging, threading
from enum import Enum
from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple

class TrustLevel(Enum):
    UNTRUSTED = 0; LOW = 1; MEDIUM = 2; HIGH = 3; VERIFIED = 4
class EntityType(Enum):
    DEVICE="device"; USER="user"; SERVICE="service"; NETWORK="network"

@dataclass
class TrustScore:
    entity_id:str
    entity_type:EntityType
    base_trust:float
    behavioral_score:float
    authentication_score:float
    last_updated:float
    violation_count:int=0
    def current_trust(self)->float:
        age = time.time() - self.last_updated
        decay   = max(0.1, 1 - age/3600)        # hourly decay
        penalty = max(0.0, 1 - 0.1*self.violation_count)
        raw = (self.base_trust + self.behavioral_score +
               self.authentication_score)/3
        return max(0.0, min(1.0, raw*decay*penalty))
    def trust_level(self)->TrustLevel:
        v=self.current_trust()
        if v>=0.9: return TrustLevel.VERIFIED
        if v>=0.7: return TrustLevel.HIGH
        if v>=0.5: return TrustLevel.MEDIUM
        if v>=0.3: return TrustLevel.LOW
        return TrustLevel.UNTRUSTED

class ZeroTrustEngine:
    def __init__(self, cfg:Dict):
        self.cfg=cfg; self.scores:Dict[str,TrustScore]={}
        self.blocked:set[str]=set()
        self.policies = {
            TrustLevel.VERIFIED:["read","write","admin"],
            TrustLevel.HIGH:["read","write"],
            TrustLevel.MEDIUM:["read"],
            TrustLevel.LOW:[],
            TrustLevel.UNTRUSTED:[]
        }
        self.lock=threading.RLock()
        self.log=logging.getLogger("ZeroTrust")

    # ---------- internal helpers ----------
    def _update_behavior(self, ts:TrustScore, ctx:Dict):
        beh=ctx.get("behavior",{})
        pkt=beh.get("packet_rate",0); bw=beh.get("bandwidth_usage",0)
        dest=len(beh.get("connection_patterns",{}).get("destinations",[]))

        score=0.5
        if pkt>self.cfg.get("normal_packet_rate",1000): score-=0.3; ts.violation_count+=1
        if bw>self.cfg.get("normal_bandwidth",10_000_000): score-=0.2; ts.violation_count+=1
        if dest>self.cfg.get("max_destinations",50): score-=0.2; ts.violation_count+=1
        ts.behavioral_score=max(-0.5, min(0.5, score))

    def _update_auth(self, ts:TrustScore, ctx:Dict):
        auth=ctx.get("authentication",{})
        score=0.0
        if auth.get("mfa_verified"): score+=0.3
        if auth.get("cert_valid"):  score+=0.2
        fresh=auth.get("last_successful_auth",0)
        if fresh: score+=max(0,1-(time.time()-fresh)/3600)*0.3
        fails=auth.get("failed_attempts",0)
        if fails>3: score-=0.2; ts.violation_count+=fails
        ts.authentication_score=max(-0.5,min(0.5,score))

    # ---------- public API ----------
    def evaluate_entity(self,eid:str,etype:EntityType,ctx:Dict)->Tuple[TrustLevel,str]:
        with self.lock:
            if eid in self.blocked:
                return TrustLevel.UNTRUSTED,"entity blocked"

            ts=self.scores.get(eid)
            if not ts:
                ts=TrustScore(eid,etype,0.5,0.0,0.0,time.time())
                self.scores[eid]=ts
            self._update_behavior(ts,ctx)
            self._update_auth(ts,ctx)
            ts.last_updated=time.time()

            lvl=ts.trust_level()
            reason=f"trust={ts.current_trust():.2f} violations={ts.violation_count}"
            if lvl==TrustLevel.UNTRUSTED:
                self.blocked.add(eid)
                self.log.warning("Blocking %s (%s)",eid,reason)
            return lvl,reason

    def check_access(self,eid:str,action:str,ctx:Dict)->Tuple[bool,str]:
        lvl,why=self.evaluate_entity(eid,EntityType.DEVICE,ctx)
        ok=action in self.policies[lvl]
        return ok,f"{lvl.name}: {why}"

    # ---------- metrics ----------
    def stats(self)->Dict:
        distr={l.name:0 for l in TrustLevel}
        for s in self.scores.values(): distr[s.trust_level().name]+=1
        return {"entities":len(self.scores),"distribution":distr,
                "blocked":len(self.blocked)}
