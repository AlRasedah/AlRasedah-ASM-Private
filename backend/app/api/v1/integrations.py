"""Integrations (notification channels), notification policies and scanner credentials."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from asm_sensors.registry import describe_adapters
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import Principal, get_db, require
from app.auth.permissions import Permission
from app.core.errors import NotFound, ValidationFailed
from app.integrations import providers as provider_info
from app.integrations.channels import CHANNELS, ChannelError
from app.integrations.notifications import send_test
from app.models import Integration, NotificationDelivery, NotificationPolicy, Secret
from app.models.enums import DeliveryStatus, EventType, IntegrationType, Severity
from app.schemas.common import ORM, Input, Message
from app.services import audit, secrets
from app.services.audit import Action

router = APIRouter(tags=["integrations"])


class IntegrationOut(ORM):
    id: uuid.UUID
    name: str
    integration_type: IntegrationType
    config: dict[str, Any]
    has_secret: bool = False
    enabled: bool
    last_success_at: datetime | None
    last_error: str | None
    last_error_at: datetime | None
    created_at: datetime


class IntegrationCreate(Input):
    name: str = Field(min_length=1, max_length=128)
    integration_type: IntegrationType
    config: dict[str, Any] = {}
    secret: str | None = Field(default=None, max_length=4096)
    enabled: bool = True


class IntegrationUpdate(Input):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    config: dict[str, Any] | None = None
    secret: str | None = Field(default=None, max_length=4096)
    clear_secret: bool = False
    enabled: bool | None = None


class IntegrationType_(BaseModel):
    type: str
    implemented: bool
    needs_secret: bool
    config_schema: dict[str, Any]


def _out(i: Integration) -> IntegrationOut:
    o = IntegrationOut.model_validate(i)
    o.has_secret = i.secret_id is not None
    return o


def _validate(itype: IntegrationType, config: dict[str, Any]) -> dict[str, Any]:
    channel = CHANNELS[itype.value]
    if not channel.implemented:
        raise ValidationFailed(f"The {itype.value} integration is planned but not yet available")
    try:
        return channel.validate(config)
    except ValidationError as exc:
        raise ValidationFailed("Invalid integration configuration",
                               details=[{"loc": e["loc"], "msg": e["msg"]} for e in exc.errors()]) from exc


@router.get("/integrations/types", response_model=list[IntegrationType_])
def types(_: Principal = Depends(require(Permission.INTEGRATIONS_READ))) -> list:
    """Channels that can be used today. Planned ones (Jira, ServiceNow) are not offered
    until they work — they stay in the code and the developer docs."""
    return [IntegrationType_(type=k, implemented=c.implemented, needs_secret=c.needs_secret,
                             config_schema=c.config_model.model_json_schema())
            for k, c in CHANNELS.items() if c.implemented]


@router.get("/integrations", response_model=list[IntegrationOut])
def list_integrations(_: Principal = Depends(require(Permission.INTEGRATIONS_READ)), db: Session = Depends(get_db)) -> list:
    return [_out(i) for i in db.execute(select(Integration).order_by(Integration.name)).scalars()]


@router.post("/integrations", response_model=IntegrationOut, status_code=201)
def create_integration(body: IntegrationCreate, principal: Principal = Depends(require(Permission.INTEGRATIONS_WRITE)),
                       db: Session = Depends(get_db)) -> IntegrationOut:
    tid = principal.require_tenant()
    config = _validate(body.integration_type, body.config)
    integ = Integration(tenant_id=tid, name=body.name, integration_type=body.integration_type, config=config,
                        enabled=body.enabled, created_by=principal.user_id)
    db.add(integ)
    db.flush()
    if body.secret:
        integ.secret_id = secrets.put_secret(db, tenant_id=tid, name=f"integration:{integ.id}", value=body.secret,
                                             kind="integration", provider=body.integration_type.value,
                                             user_id=principal.user_id).id
    audit.record(db, Action.INTEGRATION_CHANGED, object_type="integration", object_id=integ.id,
                 new={"name": body.name, "type": body.integration_type.value, "config": config,
                      "secret": bool(body.secret)})
    db.commit()
    return _out(integ)


def _integ(db: Session, iid: uuid.UUID) -> Integration:
    i = db.get(Integration, iid)
    if i is None:
        raise NotFound("Integration not found")
    return i


@router.patch("/integrations/{integration_id}", response_model=IntegrationOut)
def update_integration(integration_id: uuid.UUID, body: IntegrationUpdate,
                       principal: Principal = Depends(require(Permission.INTEGRATIONS_WRITE)),
                       db: Session = Depends(get_db)) -> IntegrationOut:
    i = _integ(db, integration_id)
    before = {"name": i.name, "config": i.config, "enabled": i.enabled, "secret": i.secret_id is not None}
    if body.name:
        i.name = body.name
    if body.config is not None:
        i.config = _validate(i.integration_type, body.config)
    if body.enabled is not None:
        i.enabled = body.enabled
    if body.clear_secret and i.secret_id:
        sid, i.secret_id = i.secret_id, None
        db.flush()
        secrets.delete_secret(db, sid)
    elif body.secret:
        i.secret_id = secrets.put_secret(db, tenant_id=i.tenant_id, name=f"integration:{i.id}", value=body.secret,
                                         kind="integration", provider=i.integration_type.value,
                                         user_id=principal.user_id).id
    after = {"name": i.name, "config": i.config, "enabled": i.enabled, "secret": i.secret_id is not None,
             **({"secret_rotated": True} if body.secret else {})}
    prev, new = audit.diff(before, after)
    audit.record(db, Action.INTEGRATION_CHANGED, object_type="integration", object_id=i.id, previous=prev, new=new)
    db.commit()
    return _out(i)


@router.delete("/integrations/{integration_id}", response_model=Message)
def delete_integration(integration_id: uuid.UUID, _: Principal = Depends(require(Permission.INTEGRATIONS_WRITE)),
                       db: Session = Depends(get_db)) -> Message:
    i = _integ(db, integration_id)
    sid = i.secret_id
    audit.record(db, Action.INTEGRATION_CHANGED, object_type="integration", object_id=i.id,
                 previous={"name": i.name}, new={"deleted": True})
    db.delete(i)
    db.flush()
    if sid:
        secrets.delete_secret(db, sid)
    db.commit()
    return Message(message="Integration deleted")


@router.post("/integrations/{integration_id}/test", response_model=Message)
def test_integration(integration_id: uuid.UUID, _: Principal = Depends(require(Permission.INTEGRATIONS_WRITE)),
                     db: Session = Depends(get_db)) -> Message:
    i = _integ(db, integration_id)
    try:
        send_test(db, i)
    except ChannelError as exc:
        raise ValidationFailed(f"Test delivery failed: {exc}") from exc
    db.commit()
    return Message(message="Test notification delivered")


# -------------------------------------------------------- notification policies
class PolicyOut(ORM):
    id: uuid.UUID
    name: str
    enabled: bool
    event_types: list[str]
    min_severity: Severity
    organization_ids: list[uuid.UUID] | None
    integration_ids: list[uuid.UUID]
    include_baseline: bool
    throttle_minutes: int


class PolicyIn(Input):
    name: str = Field(min_length=1, max_length=128)
    enabled: bool = True
    event_types: list[EventType] = []
    min_severity: Severity = Severity.HIGH
    organization_ids: list[uuid.UUID] | None = None
    integration_ids: list[uuid.UUID] = Field(min_length=1, max_length=20)
    include_baseline: bool = False
    throttle_minutes: int = Field(default=0, ge=0, le=10080)


def _check_integrations(db: Session, ids: list[uuid.UUID]) -> None:
    found = {i for (i,) in db.execute(select(Integration.id).where(Integration.id.in_(ids)))}
    if missing := set(ids) - found:
        raise ValidationFailed(f"Unknown integration(s): {', '.join(map(str, missing))}")


@router.get("/integrations/policies", response_model=list[PolicyOut], include_in_schema=True)
def list_policies(_: Principal = Depends(require(Permission.INTEGRATIONS_READ)), db: Session = Depends(get_db)) -> list:
    return list(db.execute(select(NotificationPolicy).order_by(NotificationPolicy.name)).scalars())


@router.post("/integrations/policies", response_model=PolicyOut, status_code=201)
def create_policy(body: PolicyIn, principal: Principal = Depends(require(Permission.INTEGRATIONS_WRITE)),
                  db: Session = Depends(get_db)) -> NotificationPolicy:
    _check_integrations(db, body.integration_ids)
    p = NotificationPolicy(tenant_id=principal.require_tenant(), **{**body.model_dump(), "event_types": [
        e.value for e in body.event_types]})
    db.add(p)
    db.flush()
    audit.record(db, Action.POLICY_CHANGED, object_type="notification_policy", object_id=p.id,
                 new=body.model_dump(mode="json"))
    db.commit()
    return p


@router.put("/integrations/policies/{policy_id}", response_model=PolicyOut)
def update_policy(policy_id: uuid.UUID, body: PolicyIn, _: Principal = Depends(require(Permission.INTEGRATIONS_WRITE)),
                  db: Session = Depends(get_db)) -> NotificationPolicy:
    p = db.get(NotificationPolicy, policy_id)
    if p is None:
        raise NotFound("Policy not found")
    _check_integrations(db, body.integration_ids)
    before = PolicyOut.model_validate(p).model_dump(mode="json")
    for k, v in body.model_dump().items():
        setattr(p, k, [e.value for e in body.event_types] if k == "event_types" else v)
    audit.record(db, Action.POLICY_CHANGED, object_type="notification_policy", object_id=p.id, previous=before,
                 new=body.model_dump(mode="json"))
    db.commit()
    return p


@router.delete("/integrations/policies/{policy_id}", response_model=Message)
def delete_policy(policy_id: uuid.UUID, _: Principal = Depends(require(Permission.INTEGRATIONS_WRITE)),
                  db: Session = Depends(get_db)) -> Message:
    p = db.get(NotificationPolicy, policy_id)
    if p is None:
        raise NotFound("Policy not found")
    audit.record(db, Action.POLICY_CHANGED, object_type="notification_policy", object_id=p.id,
                 previous={"name": p.name}, new={"deleted": True})
    db.delete(p)
    db.commit()
    return Message(message="Policy deleted")


class DeliveryOut(ORM):
    id: uuid.UUID
    event_id: uuid.UUID | None
    policy_id: uuid.UUID | None
    integration_id: uuid.UUID | None
    status: DeliveryStatus
    attempts: int
    last_error: str | None
    created_at: datetime
    sent_at: datetime | None


@router.get("/integrations/deliveries", response_model=list[DeliveryOut])
def deliveries(_: Principal = Depends(require(Permission.INTEGRATIONS_READ)), db: Session = Depends(get_db)) -> list:
    return list(db.execute(select(NotificationDelivery).order_by(NotificationDelivery.created_at.desc()).limit(200)).scalars())


# ------------------------------------------------------ scanner credentials
class CredentialOut(ORM):
    id: uuid.UUID
    provider: str | None
    name: str
    last_four: str | None
    updated_at: datetime


class CredentialIn(Input):
    value: str = Field(min_length=4, max_length=4096,
                       description="API key, or a JSON list of keys for providers that rotate multiple keys")


class ProviderOut(BaseModel):
    provider: str
    used_by: list[str]
    # Explanation shown in the UI and the user guide (app/integrations/providers.py).
    label: str
    description: str
    group: str
    group_label: str
    key_format: str
    paid: bool
    url: str | None = None
    testable: bool = False


@router.get("/credentials/providers", response_model=list[ProviderOut], tags=["credentials"])
def providers(_: Principal = Depends(require(Permission.INTEGRATIONS_READ))) -> list:
    used: dict[str, list[str]] = {}
    for a in describe_adapters():
        for p in a["credential_providers"]:
            used.setdefault(p, []).append(a["display_name"])
    out = []
    for key, engines in used.items():
        if not provider_info.is_available(key):
            continue  # a dead upstream: never offer a key that cannot return anything
        meta = provider_info.describe(key)
        out.append(ProviderOut(provider=key, used_by=sorted(set(engines)), label=meta["label"],
                               description=meta["description"], group=meta["group"],
                               group_label=provider_info.GROUPS[meta["group"]], key_format=meta["key_format"],
                               paid=meta["paid"], url=meta["url"], testable=key in CREDENTIAL_TESTS))
    return sorted(out, key=lambda p: (p.group, p.label))


def _test_shodan(key: str) -> str:
    """Ask Shodan about the account the key belongs to (costs no credits)."""
    import httpx

    try:
        r = httpx.get("https://api.shodan.io/api-info", params={"key": key}, timeout=15,
                      headers={"User-Agent": "Exteriq-ASM"})
    except httpx.HTTPError as exc:
        raise ValidationFailed(f"Could not reach Shodan: {type(exc).__name__}") from exc
    if r.status_code in (401, 403):
        raise ValidationFailed("Shodan rejected this key.")
    if r.status_code != 200:
        raise ValidationFailed(f"Shodan answered HTTP {r.status_code}.")
    info = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    plan = info.get("plan") or "unknown"
    return (f"Key accepted. Plan: {plan}; query credits left: {info.get('query_credits', '?')}; "
            f"scan credits left: {info.get('scan_credits', '?')}.")


# Providers whose key can be checked against the service from here.
CREDENTIAL_TESTS = {"shodan": _test_shodan}


@router.post("/credentials/{provider}/test", response_model=Message, tags=["credentials"])
def test_credential(provider: str, principal: Principal = Depends(require(Permission.CREDENTIALS_WRITE)),
                    db: Session = Depends(get_db)) -> Message:
    """Check a stored key against the provider, so a wrong key is not discovered mid-scan."""
    check = CREDENTIAL_TESTS.get(provider)
    if check is None:
        raise ValidationFailed(f"Keys for '{provider}' cannot be checked automatically yet.")
    s = db.execute(select(Secret).where(Secret.kind == "scanner_credential",
                                        Secret.provider == provider)).scalar_one_or_none()
    if s is None:
        raise NotFound("No key is stored for this provider")
    return Message(message=check(secrets.get_secret_value(db, s.id)))


@router.get("/credentials", response_model=list[CredentialOut], tags=["credentials"])
def list_credentials(_: Principal = Depends(require(Permission.INTEGRATIONS_READ)), db: Session = Depends(get_db)) -> list:
    return list(db.execute(select(Secret).where(Secret.kind == "scanner_credential").order_by(Secret.provider)).scalars())


@router.put("/credentials/{provider}", response_model=CredentialOut, tags=["credentials"])
def set_credential(provider: str, body: CredentialIn, principal: Principal = Depends(require(Permission.CREDENTIALS_WRITE)),
                   db: Session = Depends(get_db)) -> Secret:
    if reason := provider_info.UNAVAILABLE.get(provider):
        raise ValidationFailed(f"{provider_info.describe(provider)['label']} cannot be used: {reason}")
    known = {p.provider for p in providers(principal)}  # only providers an engine actually consumes
    if provider not in known:
        raise ValidationFailed(f"Unknown provider '{provider}'")
    s = secrets.put_secret(db, tenant_id=principal.require_tenant(), name=f"scanner:{provider}", value=body.value,
                           kind="scanner_credential", provider=provider, user_id=principal.user_id)
    db.commit()
    return s


@router.delete("/credentials/{credential_id}", response_model=Message, tags=["credentials"])
def delete_credential(credential_id: uuid.UUID, _: Principal = Depends(require(Permission.CREDENTIALS_WRITE)),
                      db: Session = Depends(get_db)) -> Message:
    s = db.get(Secret, credential_id)
    if s is None or s.kind != "scanner_credential":
        raise NotFound("Credential not found")
    secrets.delete_secret(db, credential_id)
    db.commit()
    return Message(message="Credential deleted")
