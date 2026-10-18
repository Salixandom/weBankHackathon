"""ClearTrade API: app factory + routes (BUILD_PLAN M7).

Endpoints:
  GET    /health
  POST   /deals
  POST   /deals/{id}/documents      (multipart upload; size/type allowlist)
  POST   /deals/{id}/run
  GET    /deals/{id}
  GET    /deals/{id}/stream         (SSE: node_started/node_finished/interrupt/...)
  POST   /deals/{id}/resume
  GET    /deals/{id}/audit
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.api.deals import DealRunner
from app.config import Settings, get_settings
from app.security.storage import DocumentStore

SYNTHETIC_BADGE = {"synthetic_data": True}  # every response carries the demo label (rule 0.10)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(title="ClearTrade", version="0.1.0")
    docs = DocumentStore(Path("data/uploads"))
    runner = DealRunner(settings, docs)
    app.state.runner = runner

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok", "env": settings.env, **SYNTHETIC_BADGE}

    @app.post("/deals")
    async def create_deal() -> dict[str, Any]:
        # Single synthetic tenant in the local demo. Never trust a tenant id
        # supplied by an unauthenticated caller.
        rec = runner.create_deal("demo-tenant")
        return {"deal_id": rec.state.deal_id, **SYNTHETIC_BADGE}

    @app.post("/deals/{deal_id}/documents")
    async def upload_document(
        deal_id: str,
        file: Annotated[UploadFile, File()],
        kind: Annotated[str, Form()] = "unknown",
    ) -> dict[str, Any]:
        if deal_id not in runner.deals:
            raise HTTPException(404, "unknown deal")
        assert file.filename is not None
        mime = file.content_type or "application/octet-stream"
        if mime not in settings.upload_allowed_types:
            raise HTTPException(415, f"file type {mime} not allowed")
        chunks: list[bytes] = []
        total = 0
        while chunk := await file.read(64 * 1024):
            total += len(chunk)
            if total > settings.upload_max_bytes:
                raise HTTPException(413, "file too large")
            chunks.append(chunk)
        data = b"".join(chunks)
        signatures = {
            "application/pdf": lambda b: b.startswith(b"%PDF-"),
            "image/jpeg": lambda b: b.startswith(b"\xff\xd8\xff"),
            "image/png": lambda b: b.startswith(b"\x89PNG\r\n\x1a\n"),
        }
        signature_check = signatures.get(mime)
        if signature_check is None or not signature_check(data):
            raise HTTPException(415, "file contents do not match the declared type")
        # malware scan hook point (ClamAV in prod; demo deals are synthetic)
        ref = runner.add_document(deal_id, data, file.filename, mime, kind)
        return {"doc_id": ref.doc_id, "sha256": ref.sha256, **SYNTHETIC_BADGE}

    background_tasks: set[asyncio.Task] = set()

    @app.post("/deals/{deal_id}/run")
    async def run_deal(deal_id: str) -> dict[str, Any]:
        if deal_id not in runner.deals:
            raise HTTPException(404, "unknown deal")
        if runner.deals[deal_id].running:
            raise HTTPException(409, "deal already running")
        task = asyncio.create_task(runner.run(deal_id))
        background_tasks.add(task)
        task.add_done_callback(background_tasks.discard)
        return {"started": True, "stream": f"/deals/{deal_id}/stream", **SYNTHETIC_BADGE}

    @app.get("/deals/{deal_id}")
    async def get_deal(deal_id: str) -> dict[str, Any]:
        try:
            rec = runner.deals[deal_id]
        except KeyError:
            raise HTTPException(404, "unknown deal") from None
        return {"state": rec.state.model_dump(), "running": rec.running, **SYNTHETIC_BADGE}

    @app.get("/deals/{deal_id}/stream")
    async def stream_deal(deal_id: str) -> StreamingResponse:
        if deal_id not in runner.deals:
            raise HTTPException(404, "unknown deal")
        rec = runner.deals[deal_id]

        async def gen():
            # replay any queued events, then follow live until done
            while True:
                try:
                    event = await asyncio.wait_for(rec.queue.get(), timeout=30.0)
                except TimeoutError:
                    yield f"event: ping\ndata: {json.dumps(SYNTHETIC_BADGE)}\n\n"
                    continue
                yield f"event: {event['type']}\ndata: {json.dumps(event, default=str)}\n\n"
                if event["type"] in ("done", "error"):
                    break

        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.post("/deals/{deal_id}/resume")
    async def resume_deal(deal_id: str, payload: ResumeBody) -> dict[str, Any]:
        if deal_id not in runner.deals:
            raise HTTPException(404, "unknown deal")
        if runner.deals[deal_id].running:
            raise HTTPException(409, "deal already running")
        task = asyncio.create_task(runner.resume(deal_id, payload.model_dump(exclude_none=True)))
        background_tasks.add(task)
        task.add_done_callback(background_tasks.discard)
        return {"resumed": True, **SYNTHETIC_BADGE}

    @app.post("/deals/{deal_id}/sign_demo")
    async def sign_demo(deal_id: str) -> dict[str, Any]:
        if settings.env != "demo":
            raise HTTPException(403, "demo signing unavailable in non-demo environment")
        if deal_id not in runner.deals:
            raise HTTPException(404, "unknown deal")
        rec = runner.deals[deal_id]
        import base64
        from datetime import UTC, datetime

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from app.graph.state import SignedApproval, new_id
        from app.security.approval import (
            DEMO_APPROVER_ID,
            DEMO_PRIVATE_KEY_B64,
            approval_render,
            deal_hash,
            sign_approval,
        )

        priv_bytes = base64.b64decode(DEMO_PRIVATE_KEY_B64)
        priv_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
        render_data = approval_render(rec.state)
        h = deal_hash(render_data)
        now_str = datetime.now(UTC).isoformat()
        approval = SignedApproval(
            deal_hash=h,
            approver_id=DEMO_APPROVER_ID,
            method="webauthn_passkey",
            signature_b64="",
            signed_at=now_str,
            nonce=new_id("nonce"),
        )
        sig = sign_approval(approval, priv_key)
        signed = approval.model_copy(update={"signature_b64": sig})
        return {"approval": signed.model_dump(), **SYNTHETIC_BADGE}

    @app.post("/deals/seed/{seed_id}")
    async def load_seed_deal(seed_id: str) -> dict[str, Any]:
        """One-click demo deal loader (M10 Demo Hardening).
        Loads synthetic seed deal PDFs (e.g. seed-01 clean, seed-06 fixable discrepancy)
        directly into a new deal record ready to run."""
        seed_dir = Path(__file__).resolve().parents[1] / "seed" / "deals" / "pdfs" / seed_id
        if not seed_dir.is_dir():
            raise HTTPException(404, f"seed deal {seed_id!r} not found")
        rec = runner.create_deal("demo-tenant")
        for pdf_path in sorted(seed_dir.glob("*.pdf")):
            data = pdf_path.read_bytes()
            kind = "unknown"
            name_lower = pdf_path.name.lower()
            if "lc" in name_lower:
                kind = "letter_of_credit"
            elif "inv" in name_lower:
                kind = "commercial_invoice"
            elif "pl" in name_lower:
                kind = "packing_list"
            runner.add_document(rec.state.deal_id, data, pdf_path.name, "application/pdf", kind)
        return {"deal_id": rec.state.deal_id, "seed_id": seed_id, **SYNTHETIC_BADGE}

    @app.get("/deals/{deal_id}/audit")
    async def deal_audit(deal_id: str) -> dict[str, Any]:
        if deal_id not in runner.deals:
            raise HTTPException(404, "unknown deal")
        return {
            "events": runner.audit_trail(deal_id),
            "chain_ok": runner.audit.verify_chain(runner.deals[deal_id].state.tenant_id),
            **SYNTHETIC_BADGE,
        }

    # Mount WeChat channel router (M8)
    from app.channels.wechat.client import InMemoryTokenCache, WechatClient
    from app.channels.wechat.router import WechatDeps, create_wechat_router

    wx_client = WechatClient(
        app_id="wx_weBank_demo",
        app_secret="demo_secret",
        cache=InMemoryTokenCache(),
    )
    deps = WechatDeps(wx_client, runner, "demo_callback_token")
    app.include_router(create_wechat_router(deps))

    return app


class ResumeBody(BaseModel):
    action: str = "resolve"
    approval: dict[str, Any] | None = None
    note: str = ""


def _module_app() -> FastAPI | None:
    """ASGI entrypoint for `uvicorn app.main:app`. Building settings requires
    env (virtual key + signing key); tests build their own app instead."""
    try:
        settings = get_settings()
        if not settings.litellm_virtual_key:
            return None
        return create_app(settings)
    except Exception:
        return None


app = _module_app()
