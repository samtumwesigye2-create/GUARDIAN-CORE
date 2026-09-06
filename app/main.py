from __future__ import annotations
import os, time
from typing import Any, Literal
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
try:
    import psycopg
    from psycopg.rows import dict_row
except Exception:
    psycopg = None

app = FastAPI(title="UNG GUARDIAN", version="0.1.0")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
SERVICE_TOKEN = os.environ.get("GUARDIAN_SERVICE_TOKEN", "")

SCHEMA = """
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS guardian_system_registry (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), system_key TEXT NOT NULL UNIQUE,
 display_name TEXT NOT NULL, category TEXT NOT NULL, criticality TEXT NOT NULL DEFAULT 'medium',
 trust_level TEXT NOT NULL DEFAULT 'standard', permitted_categories TEXT[] NOT NULL DEFAULT ARRAY['data_quality','performance'],
 connection_type TEXT NOT NULL, connection_ref TEXT, expected_heartbeat_interval_seconds INTEGER,
 is_active BOOLEAN NOT NULL DEFAULT true, onboarded_at TIMESTAMPTZ NOT NULL DEFAULT now(), deactivated_at TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS guardian_system_heartbeats (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), system_id UUID NOT NULL REFERENCES guardian_system_registry(id),
 received_at TIMESTAMPTZ NOT NULL DEFAULT now(), status TEXT NOT NULL DEFAULT 'ok', metrics_json JSONB);
CREATE INDEX IF NOT EXISTS idx_guardian_heartbeats_recent ON guardian_system_heartbeats(system_id, received_at DESC);
CREATE TABLE IF NOT EXISTS guardian_findings (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), system_id UUID REFERENCES guardian_system_registry(id), category TEXT NOT NULL,
 entity_type TEXT NOT NULL, entity_id TEXT, severity TEXT NOT NULL, summary TEXT NOT NULL, evidence_json JSONB,
 status TEXT NOT NULL DEFAULT 'open', detected_at TIMESTAMPTZ NOT NULL DEFAULT now(), resolved_at TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS guardian_fix_proposals (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), finding_id UUID NOT NULL REFERENCES guardian_findings(id) ON DELETE CASCADE,
 system_id UUID NOT NULL REFERENCES guardian_system_registry(id), proposed_action TEXT NOT NULL, change_json JSONB NOT NULL,
 category TEXT NOT NULL, risk_level TEXT NOT NULL, requires_approval BOOLEAN NOT NULL DEFAULT true,
 approved_by TEXT, approved_at TIMESTAMPTZ, auto_applied BOOLEAN NOT NULL DEFAULT false,
 applied_at TIMESTAMPTZ, rolled_back_at TIMESTAMPTZ, status TEXT NOT NULL DEFAULT 'pending');
CREATE TABLE IF NOT EXISTS guardian_action_log (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), system_id UUID REFERENCES guardian_system_registry(id),
 action_type TEXT NOT NULL, actor_ref TEXT NOT NULL, details_json JSONB, occurred_at TIMESTAMPTZ NOT NULL DEFAULT now());
"""

PROTECTED = {"finance","payroll","benefits","compensation","tax","tax_filing","vault","secrets","code_patch","infrastructure_config"}

def auth(x_service_token: str):
    if not SERVICE_TOKEN or x_service_token != SERVICE_TOKEN:
        raise HTTPException(401, "Invalid service token")

def conn():
    if not DATABASE_URL or psycopg is None:
        raise HTTPException(503, "Database is not configured")
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)

@app.on_event("startup")
def init_db():
    if DATABASE_URL and psycopg is not None:
        with psycopg.connect(DATABASE_URL) as c:
            c.execute(SCHEMA)

@app.get('/health')
def health():
    return {"status":"ok","service":"guardian","version":"0.1.0"}

class SystemIn(BaseModel):
    system_key:str; display_name:str; category:str; criticality:str='medium'; trust_level:str='standard'
    connection_type:str='heartbeat_push'; connection_ref:str|None=None; expected_heartbeat_interval_seconds:int|None=60

@app.post('/systems')
def register_system(body:SystemIn, x_service_token:str=Header(default="")):
    auth(x_service_token)
    with conn() as c:
        row=c.execute("""INSERT INTO guardian_system_registry(system_key,display_name,category,criticality,trust_level,connection_type,connection_ref,expected_heartbeat_interval_seconds)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(system_key) DO UPDATE SET display_name=EXCLUDED.display_name RETURNING *""",
        (body.system_key,body.display_name,body.category,body.criticality,body.trust_level,body.connection_type,body.connection_ref,body.expected_heartbeat_interval_seconds)).fetchone()
        return row

class HeartbeatIn(BaseModel):
    status:Literal['ok','degraded','error']='ok'; metrics:dict[str,Any]={}

@app.post('/systems/{system_key}/heartbeat')
def heartbeat(system_key:str, body:HeartbeatIn, x_service_token:str=Header(default="")):
    auth(x_service_token)
    with conn() as c:
        sys=c.execute("SELECT id FROM guardian_system_registry WHERE system_key=%s AND is_active=true",(system_key,)).fetchone()
        if not sys: raise HTTPException(404,"Unknown system")
        c.execute("INSERT INTO guardian_system_heartbeats(system_id,status,metrics_json) VALUES(%s,%s,%s)",(sys['id'],body.status,body.metrics))
        return {"accepted":True,"system_key":system_key,"status":body.status,"received_at":time.time()}

class FindingIn(BaseModel):
    system_key:str; category:str; entity_type:str; entity_id:str|None=None; severity:str='medium'; summary:str; evidence:dict[str,Any]={}

@app.post('/findings')
def finding(body:FindingIn, x_service_token:str=Header(default="")):
    auth(x_service_token)
    with conn() as c:
        sys=c.execute("SELECT id FROM guardian_system_registry WHERE system_key=%s",(body.system_key,)).fetchone()
        if not sys: raise HTTPException(404,"Unknown system")
        row=c.execute("""INSERT INTO guardian_findings(system_id,category,entity_type,entity_id,severity,summary,evidence_json)
        VALUES(%s,%s,%s,%s,%s,%s,%s) RETURNING *""",(sys['id'],body.category,body.entity_type,body.entity_id,body.severity,body.summary,body.evidence)).fetchone()
        return row

class ProposalIn(BaseModel):
    finding_id:str; system_key:str; proposed_action:str; change:dict[str,Any]; category:str; risk_level:Literal['low','medium','high']='medium'

@app.post('/fix-proposals')
def proposal(body:ProposalIn, x_service_token:str=Header(default="")):
    auth(x_service_token)
    protected = body.category.lower() in PROTECTED
    requires = protected or body.risk_level != 'low'
    with conn() as c:
        sys=c.execute("SELECT id,permitted_categories FROM guardian_system_registry WHERE system_key=%s",(body.system_key,)).fetchone()
        if not sys: raise HTTPException(404,"Unknown system")
        if body.category not in (sys['permitted_categories'] or []): requires=True
        row=c.execute("""INSERT INTO guardian_fix_proposals(finding_id,system_id,proposed_action,change_json,category,risk_level,requires_approval)
        VALUES(%s,%s,%s,%s,%s,%s,%s) RETURNING *""",(body.finding_id,sys['id'],body.proposed_action,body.change,body.category,body.risk_level,requires)).fetchone()
        return row
