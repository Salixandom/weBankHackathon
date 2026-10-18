"""Deal runner service: owns compiled graphs per deal, streams events.

Demo-grade: in-memory deal registry + per-deal asyncio queues for SSE.
Production would swap the registry for the DB and the checkpointer for
Postgres; the graph code does not change.
"""

from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import dataclass, field
from typing import Any

from app.audit.anchor import MockAnchor
from app.audit.events import GENESIS, AuditEvent, AuditSink
from app.config import Settings
from app.graph.build import build_graph
from app.graph.nodes.extract_doc import ALLOWED_KINDS as ALLOWED_DOC_KINDS
from app.graph.state import DealState, DocRef, new_id
from app.harness.budget import DealBudget
from app.harness.hooks import NodeContext
from app.harness.llm import LLMClient
from app.security.approval import ApprovalVerifier
from app.security.storage import DocumentStore
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from langgraph.checkpoint.memory import InMemorySaver
from redis import Redis


@dataclass
class DealRecord:
    state: DealState
    queue: asyncio.Queue[dict[str, Any]] = field(default_factory=asyncio.Queue)
    thread_id: str = ""
    running: bool = False


class EventfulAuditSink(AuditSink):
    """Forwards every audit event to the deal's SSE queue and keeps the chain."""

    def __init__(self, runner: DealRunner) -> None:
        self._runner = runner
        self._fallback = InMemoryChainForwarder()

    def emit(self, event: AuditEvent) -> str:
        h = self._fallback.emit(event)
        rec = self._runner.deals.get(event.deal_id)
        if rec is not None:
            etype = "interrupt" if event.kind == "node_interrupted" else event.kind
            rec.queue.put_nowait(
                {
                    "type": etype,
                    "node": event.payload.get("node", ""),
                    "ts": event.ts,
                    # interrupt details are attached by the nodes via interrupt()
                    # and live in the langgraph event, not the audit payload;
                    # the UI falls back to fetching deal state for them.
                    "payload": event.payload,
                }
            )
        return h

    def head(self, tenant_id: str) -> str:
        return self._fallback.head(tenant_id)

    def verify_chain(self, tenant_id: str) -> bool:
        return self._fallback.verify_chain(tenant_id)

    @property
    def events(self) -> list[tuple[AuditEvent, str]]:
        return self._fallback.events


class InMemoryChainForwarder(AuditSink):
    def __init__(self) -> None:
        self.events: list[tuple[AuditEvent, str]] = []
        self._heads: dict[str, str] = {}

    def emit(self, event: AuditEvent) -> str:
        prev = self._heads.get(event.tenant_id, GENESIS)
        h = event.chain(prev)
        self.events.append((event, h))
        self._heads[event.tenant_id] = h
        return h

    def head(self, tenant_id: str) -> str:
        return self._heads.get(tenant_id, GENESIS)

    def verify_chain(self, tenant_id: str) -> bool:
        prev = GENESIS
        for event, h in self.events:
            if event.tenant_id != tenant_id:
                continue
            if event.chain(prev) != h:
                return False
            prev = h
        return True


class DealRunner:
    def __init__(self, settings: Settings, docs: DocumentStore):
        self.settings = settings
        self.docs = docs
        self.deals: dict[str, DealRecord] = {}
        self._checkpointers: dict[str, InMemorySaver] = {}
        self.audit = EventfulAuditSink(self)
        self.anchor = MockAnchor()
        if settings.redis_url.startswith("fakeredis"):
            import fakeredis

            self.idempotency = fakeredis.FakeRedis(decode_responses=True)
        else:
            try:
                import socket
                from urllib.parse import urlparse

                parsed = urlparse(settings.redis_url)
                host = parsed.hostname or "localhost"
                port = parsed.port or 6379
                with socket.create_connection((host, port), timeout=0.1):
                    pass
                self.idempotency = Redis.from_url(settings.redis_url, decode_responses=True)
            except Exception:
                if settings.env == "demo":
                    import fakeredis

                    self.idempotency = fakeredis.FakeRedis(decode_responses=True)
                else:
                    self.idempotency = Redis.from_url(settings.redis_url, decode_responses=True)
        raw_keys = json.loads(settings.approval_public_keys_json)
        if not raw_keys and settings.env == "demo":
            from app.security.approval import DEMO_APPROVER_ID, DEMO_PUBLIC_KEY_B64

            raw_keys = {DEMO_APPROVER_ID: DEMO_PUBLIC_KEY_B64}
        self.approval_verifier = ApprovalVerifier(
            {
                name: Ed25519PublicKey.from_public_bytes(base64.b64decode(value, validate=True))
                for name, value in raw_keys.items()
            }
        )
        self.llm = LLMClient(
            base_url=settings.litellm_base_url,
            api_key=settings.litellm_virtual_key,
            timeout_s=settings.litellm_timeout_s,
        )

    # -- lifecycle ---------------------------------------------------------

    def create_deal(self, tenant_id: str, lc_ref: str | None = None) -> DealRecord:
        deal_id = new_id("deal")
        rec = DealRecord(
            state=DealState(deal_id=deal_id, tenant_id=tenant_id),
            thread_id=deal_id,
        )
        self.deals[deal_id] = rec
        self.audit.emit(
            AuditEvent(kind="deal_created", deal_id=deal_id, tenant_id=tenant_id, payload={})
        )
        return rec

    def add_document(
        self, deal_id: str, data: bytes, filename: str, mime: str, kind: str = "unknown"
    ) -> DocRef:
        rec = self._require(deal_id)
        sha = self.docs.put(data)
        ref = DocRef(
            doc_id=new_id("doc"),
            deal_id=deal_id,
            sha256=sha,
            filename=filename,
            mime=mime,
            size_bytes=len(data),
            kind=kind if kind in ALLOWED_DOC_KINDS else "unknown",
        )
        rec.state.documents.append(ref)
        self.audit.emit(
            AuditEvent(
                kind="document_registered",
                deal_id=deal_id,
                tenant_id=rec.state.tenant_id,
                payload={"doc_id": ref.doc_id, "sha256": sha, "filename": filename},
            )
        )
        return ref

    # -- run / resume ------------------------------------------------------

    def _checkpointer(self, deal_id: str) -> InMemorySaver:
        """One checkpointer per deal: interrupts must survive across
        run/resume calls (Postgres checkpointer in production)."""
        if deal_id not in self._checkpointers:
            self._checkpointers[deal_id] = InMemorySaver()
        return self._checkpointers[deal_id]

    def _graph_ctx(self, deal_id: str) -> NodeContext:
        return NodeContext(
            budget=DealBudget(
                deal_id,
                max_steps=self.settings.budget_max_steps,
                max_tokens=self.settings.budget_max_tokens_per_deal,
                max_cost_minor=self.settings.budget_max_cost_minor_per_deal,
            ),
            audit=self.audit,
            llm=self.llm,
            docs=self.docs,
            anchor=self.anchor,
            redis=self.idempotency,
            approval_verifier=self.approval_verifier,
        )

    async def run(self, deal_id: str) -> None:
        rec = self._require(deal_id)
        if rec.running:
            rec.queue.put_nowait({"type": "error", "detail": "deal already running"})
            return
        rec.running = True
        graph = build_graph(self._graph_ctx(deal_id), checkpointer=self._checkpointer(deal_id))
        config = {"configurable": {"thread_id": rec.thread_id}}
        try:
            final = await graph.ainvoke(rec.state, config)
            rec.state = DealState.model_validate(final)
            self._emit_interrupt_payload(deal_id, final)
            rec.queue.put_nowait({"type": "done", "state": rec.state.model_dump()})
        except Exception as e:
            rec.queue.put_nowait({"type": "error", "detail": type(e).__name__})
        finally:
            rec.running = False

    async def resume(self, deal_id: str, resume_payload: dict[str, Any]) -> None:
        from langgraph.types import Command

        rec = self._require(deal_id)
        if rec.running:
            rec.queue.put_nowait({"type": "error", "detail": "deal already running"})
            return
        if resume_payload.get("action") == "corrected_document":
            resume_payload = {
                **resume_payload,
                "documents": [doc.model_dump() for doc in rec.state.documents],
            }
        rec.running = True
        graph = build_graph(self._graph_ctx(deal_id), checkpointer=self._checkpointer(deal_id))
        config = {"configurable": {"thread_id": rec.thread_id}}
        try:
            final = await graph.ainvoke(Command(resume=resume_payload), config)
            rec.state = DealState.model_validate(final)
            self._emit_interrupt_payload(deal_id, final)
            rec.queue.put_nowait({"type": "done", "state": rec.state.model_dump()})
        except Exception as e:
            rec.queue.put_nowait({"type": "error", "detail": type(e).__name__})
        finally:
            rec.running = False

    def _emit_interrupt_payload(self, deal_id: str, final: Any) -> None:
        """Forward the rich interrupt payload (kind, findings, fx options,
        amendment draft, ...) to the SSE queue before done."""
        interrupts = final.get("__interrupt__") if isinstance(final, dict) else None
        if not interrupts:
            return
        rec = self.deals.get(deal_id)
        if rec is None:
            return
        for intr in interrupts:
            value = getattr(intr, "value", None)
            if isinstance(value, dict):
                rec.queue.put_nowait(
                    {"type": "interrupt", "node": value.get("kind", ""), "payload": value}
                )

    def audit_trail(self, deal_id: str) -> list[dict[str, Any]]:
        return [
            {"kind": e.kind, "payload": e.payload, "ts": e.ts, "hash": h}
            for e, h in self.audit.events
            if e.deal_id == deal_id
        ]

    def _require(self, deal_id: str) -> DealRecord:
        try:
            return self.deals[deal_id]
        except KeyError:
            raise KeyError(f"unknown deal {deal_id}") from None
