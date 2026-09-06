from __future__ import annotations

import os
import time
from contextlib import asynccontextmanager
from typing import Any, Literal

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

try:
    import psycopg
    from psycopg.rows import dict_row
except Exception:
    psycopg = None

DATABASE_URL = os.getenv("DATABASE_URL", "")
SERVICE_TOKEN = os.getenv("GUARDIAN_SERVICE_TOKEN", "")
JANUS_BASE_URL = os.getenv("JANUS_BASE_URL", "")
PULSAR_BASE_URL = os.getenv("PULSAR_BASE_URL", "")

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
CREATE TABLE IF NOT EXISTS guardian_connectors (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), connector_key TEXT NOT NULL UNIQUE,
 source_system TEXT NOT NULL, target_system TEXT NOT NULL, connector_type TEXT NOT NULL,
 expected_interval_seconds INTEGER NOT NULL DEFAULT 60, is_active BOOLEAN NOT NULL DEFAULT true,
 last_status TEXT, last_checked_at TIMESTAMPTZ, details_json JSONB);
CREATE TABLE IF NOT EXISTS guardian_findings (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), system_id UUID REFERENCES guardian_system_registry(id), category TEXT NOT NULL,
 entity_type TEXT NOT NULL, entity_id TEXT, severity TEXT NOT NULL, summary TEXT NOT NULL, evidence_json JSONB,
 status TEXT NOT NULL DEFAULT 'open', detected_at TIMESTAMPTZ NOT NULL DEFAULT now(), resolved_at TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS guardian_incidents (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), system_id UUID REFERENCES guardian_system_registry(id),
 incident_key TEXT NOT NULL UNIQUE, severity TEXT NOT NULL, title TEXT NOT NULL, summary TEXT,
 status TEXT NOT NULL DEFAULT 'open', opened_at TIMESTAMPTZ NOT NULL DEFAULT now(), acknowledged_at TIMESTAMPTZ,
 resolved_at TIMESTAMPTZ, details_json JSONB);
CREATE TABLE IF NOT EXISTS guardian_debug_sessions (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), system_id UUID REFERENCES guardian_system_registry(id),
 started_by TEXT NOT NULL, objective TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
 observations_json JSONB NOT NULL DEFAULT '{}'::jsonb, started_at TIMESTAMPTZ NOT NULL DEFAULT now(), closed_at TIMESTAMPTZ);
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

PROTECTED = {
    "finance", "payroll", "benefits", "compensation", "tax", "tax_filing",
    "vault", "secrets", "code_patch", "infrastructure_config"
}


def auth(token: str):
    if not SERVICE_TOKEN or token != SERVICE_TOKEN:
        raise HTTPException(401, "Invalid service token")


def conn():
    if not DATABASE_URL or psycopg is None:
        raise HTTPException(503, "Database is not configured")
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if DATABASE_URL and psycopg is not None:
        with psycopg.connect(DATABASE_URL) as c:
            c.execute(SCHEMA)
    yield


app = FastAPI(title="UNG GUARDIAN", version="0.3.0", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok", "service": "guardian", "version": "0.3.0"}


@app.get("/ready")
def ready():
    db_ready = False
    if DATABASE_URL and psycopg is not None:
        try:
            with psycopg.connect(DATABASE_URL, connect_timeout=3) as c:
                c.execute("SELECT 1")
            db_ready = True
        except Exception:
            pass
    return {
        "status": "ready" if db_ready else "degraded",
        "database": db_ready,
        "janus_configured": bool(JANUS_BASE_URL),
        "pulsar_configured": bool(PULSAR_BASE_URL),
    }


class SystemIn(BaseModel):
    system_key: str
    display_name: str
    category: str
    criticality: str = "medium"
    trust_level: str = "standard"
    connection_type: str = "heartbeat_push"
    connection_ref: str | None = None
    expected_heartbeat_interval_seconds: int | None = 60


@app.post("/systems")
def register_system(body: SystemIn, x_service_token: str = Header(default="")):
    auth(x_service_token)
    with conn() as c:
        return c.execute(
            """INSERT INTO guardian_system_registry(system_key,display_name,category,criticality,trust_level,connection_type,connection_ref,expected_heartbeat_interval_seconds)
               VALUES(%s,%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT(system_key) DO UPDATE SET display_name=EXCLUDED.display_name, category=EXCLUDED.category,
               criticality=EXCLUDED.criticality, trust_level=EXCLUDED.trust_level, connection_ref=EXCLUDED.connection_ref,
               expected_heartbeat_interval_seconds=EXCLUDED.expected_heartbeat_interval_seconds, is_active=true
               RETURNING *""",
            (body.system_key, body.display_name, body.category, body.criticality, body.trust_level,
             body.connection_type, body.connection_ref, body.expected_heartbeat_interval_seconds),
        ).fetchone()


class HeartbeatIn(BaseModel):
    status: Literal["ok", "degraded", "error"] = "ok"
    metrics: dict[str, Any] = Field(default_factory=dict)


@app.post("/systems/{system_key}/heartbeat")
def heartbeat(system_key: str, body: HeartbeatIn, x_service_token: str = Header(default="")):
    auth(x_service_token)
    with conn() as c:
        system = c.execute("SELECT id FROM guardian_system_registry WHERE system_key=%s AND is_active=true", (system_key,)).fetchone()
        if not system:
            raise HTTPException(404, "Unknown system")
        c.execute("INSERT INTO guardian_system_heartbeats(system_id,status,metrics_json) VALUES(%s,%s,%s)",
                  (system["id"], body.status, body.metrics))
        return {"accepted": True, "system_key": system_key, "status": body.status, "received_at": time.time()}


@app.get("/systems/{system_key}/status")
def system_status(system_key: str, x_service_token: str = Header(default="")):
    auth(x_service_token)
    with conn() as c:
        row = c.execute(
            """SELECT s.system_key,s.display_name,s.criticality,s.expected_heartbeat_interval_seconds,
                      h.status,h.received_at,h.metrics_json
               FROM guardian_system_registry s
               LEFT JOIN LATERAL (SELECT * FROM guardian_system_heartbeats h WHERE h.system_id=s.id ORDER BY received_at DESC LIMIT 1) h ON true
               WHERE s.system_key=%s""", (system_key,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Unknown system")
        stale = True
        if row["received_at"] and row["expected_heartbeat_interval_seconds"]:
            stale = (time.time() - row["received_at"].timestamp()) > row["expected_heartbeat_interval_seconds"] * 2
        return {**row, "stale": stale}


class ConnectorIn(BaseModel):
    connector_key: str
    source_system: str
    target_system: str
    connector_type: str = "http"
    expected_interval_seconds: int = Field(default=60, ge=5, le=86400)


@app.post("/connectors")
def register_connector(body: ConnectorIn, x_service_token: str = Header(default="")):
    auth(x_service_token)
    with conn() as c:
        return c.execute(
            """INSERT INTO guardian_connectors(connector_key,source_system,target_system,connector_type,expected_interval_seconds)
               VALUES(%s,%s,%s,%s,%s)
               ON CONFLICT(connector_key) DO UPDATE SET source_system=EXCLUDED.source_system,target_system=EXCLUDED.target_system,
               connector_type=EXCLUDED.connector_type,expected_interval_seconds=EXCLUDED.expected_interval_seconds,is_active=true
               RETURNING *""",
            (body.connector_key, body.source_system, body.target_system, body.connector_type, body.expected_interval_seconds),
        ).fetchone()


class ConnectorCheckIn(BaseModel):
    status: Literal["ok", "degraded", "error"]
    details: dict[str, Any] = Field(default_factory=dict)


@app.post("/connectors/{connector_key}/check")
def connector_check(connector_key: str, body: ConnectorCheckIn, x_service_token: str = Header(default="")):
    auth(x_service_token)
    with conn() as c:
        row = c.execute(
            """UPDATE guardian_connectors SET last_status=%s,last_checked_at=now(),details_json=%s
               WHERE connector_key=%s AND is_active=true RETURNING *""",
            (body.status, body.details, connector_key),
        ).fetchone()
        if not row:
            raise HTTPException(404, "Unknown connector")
        return row


class FindingIn(BaseModel):
    system_key: str
    category: str
    entity_type: str
    entity_id: str | None = None
    severity: str = "medium"
    summary: str
    evidence: dict[str, Any] = Field(default_factory=dict)


@app.post("/findings")
def finding(body: FindingIn, x_service_token: str = Header(default="")):
    auth(x_service_token)
    with conn() as c:
        system = c.execute("SELECT id FROM guardian_system_registry WHERE system_key=%s", (body.system_key,)).fetchone()
        if not system:
            raise HTTPException(404, "Unknown system")
        return c.execute(
            """INSERT INTO guardian_findings(system_id,category,entity_type,entity_id,severity,summary,evidence_json)
               VALUES(%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
            (system["id"], body.category, body.entity_type, body.entity_id, body.severity, body.summary, body.evidence),
        ).fetchone()


class IncidentIn(BaseModel):
    system_key: str
    incident_key: str
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    title: str
    summary: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


@app.post("/incidents")
def incident(body: IncidentIn, x_service_token: str = Header(default="")):
    auth(x_service_token)
    with conn() as c:
        system = c.execute("SELECT id FROM guardian_system_registry WHERE system_key=%s", (body.system_key,)).fetchone()
        if not system:
            raise HTTPException(404, "Unknown system")
        return c.execute(
            """INSERT INTO guardian_incidents(system_id,incident_key,severity,title,summary,details_json)
               VALUES(%s,%s,%s,%s,%s,%s)
               ON CONFLICT(incident_key) DO UPDATE SET severity=EXCLUDED.severity,title=EXCLUDED.title,
               summary=EXCLUDED.summary,details_json=EXCLUDED.details_json,status='open' RETURNING *""",
            (system["id"], body.incident_key, body.severity, body.title, body.summary, body.details),
        ).fetchone()


class DebugSessionIn(BaseModel):
    system_key: str
    started_by: str
    objective: str
    observations: dict[str, Any] = Field(default_factory=dict)


@app.post("/debug-sessions")
def debug_session(body: DebugSessionIn, x_service_token: str = Header(default="")):
    auth(x_service_token)
    with conn() as c:
        system = c.execute("SELECT id FROM guardian_system_registry WHERE system_key=%s", (body.system_key,)).fetchone()
        if not system:
            raise HTTPException(404, "Unknown system")
        return c.execute(
            """INSERT INTO guardian_debug_sessions(system_id,started_by,objective,observations_json)
               VALUES(%s,%s,%s,%s) RETURNING *""",
            (system["id"], body.started_by, body.objective, body.observations),
        ).fetchone()


class ProposalIn(BaseModel):
    finding_id: str
    system_key: str
    proposed_action: str
    change: dict[str, Any]
    category: str
    risk_level: Literal["low", "medium", "high"] = "medium"


@app.post("/fix-proposals")
def proposal(body: ProposalIn, x_service_token: str = Header(default="")):
    auth(x_service_token)
    protected = body.category.lower() in PROTECTED
    requires = protected or body.risk_level != "low"
    with conn() as c:
        system = c.execute("SELECT id,permitted_categories FROM guardian_system_registry WHERE system_key=%s", (body.system_key,)).fetchone()
        if not system:
            raise HTTPException(404, "Unknown system")
        if body.category not in (system["permitted_categories"] or []):
            requires = True
        return c.execute(
            """INSERT INTO guardian_fix_proposals(finding_id,system_id,proposed_action,change_json,category,risk_level,requires_approval)
               VALUES(%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
            (body.finding_id, system["id"], body.proposed_action, body.change, body.category, body.risk_level, requires),
        ).fetchone()
