"""First-run setup (public): create the first platform administrator with a one-time token."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import EmailStr, Field
from sqlalchemy.orm import Session

from app import setup
from app.api.deps import get_system_db
from app.schemas.common import Input

router = APIRouter(prefix="/setup", tags=["setup"])


class SetupIn(Input):
    token: str = Field(min_length=20, max_length=200)
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    full_name: str = Field(min_length=1, max_length=200)
    tenant_name: str = Field(default="Default", min_length=1, max_length=200)


@router.get("")
def status(db: Session = Depends(get_system_db)) -> dict[str, Any]:
    return {"needed": setup.needed(db)}


@router.post("", status_code=201)
def complete(body: SetupIn, db: Session = Depends(get_system_db)) -> dict[str, Any]:
    user = setup.complete(db, token=body.token, email=str(body.email), password=body.password,
                          full_name=body.full_name, tenant_name=body.tenant_name)
    db.commit()
    return {"email": user.email, "message": "Setup is complete. Sign in with the account you just created."}
