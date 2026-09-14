"""回归：JWT 过期与错误签名都必须被拒绝（401），合法令牌可用。"""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from jose import jwt

from app.auth import create_access_token, get_current_user
from app.config import settings


def _bearer(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def test_valid_token_accepted():
    token = create_access_token("researcher", "researcher")
    user = get_current_user(_bearer(token))
    assert user == {"username": "researcher", "role": "researcher"}


def test_expired_token_rejected():
    # 经本仓签发方式产出、但 exp 在过去
    original = settings.access_token_expire_minutes
    settings.access_token_expire_minutes = -120
    try:
        token = create_access_token("researcher", "researcher")
    finally:
        settings.access_token_expire_minutes = original

    with pytest.raises(HTTPException) as exc_info:
        get_current_user(_bearer(token))
    assert exc_info.value.status_code == 401


def test_expired_token_with_valid_signature_rejected():
    # 签名完全合法，仅 exp 过期 —— 不允许靠关 verify_exp 放行
    past_exp = datetime.now(timezone.utc) - timedelta(seconds=30)
    token = jwt.encode(
        {"sub": "researcher", "role": "researcher", "exp": past_exp},
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )
    with pytest.raises(HTTPException) as exc_info:
        get_current_user(_bearer(token))
    assert exc_info.value.status_code == 401


def test_bad_signature_token_rejected():
    future_exp = datetime.now(timezone.utc) + timedelta(minutes=10)
    token = jwt.encode(
        {"sub": "researcher", "role": "researcher", "exp": future_exp},
        "wrong-secret",
        algorithm=settings.jwt_algorithm,
    )
    with pytest.raises(HTTPException) as exc_info:
        get_current_user(_bearer(token))
    assert exc_info.value.status_code == 401


def test_missing_credentials_rejected():
    with pytest.raises(HTTPException) as exc_info:
        get_current_user(None)
    assert exc_info.value.status_code == 401
