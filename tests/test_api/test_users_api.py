from builtins import str
import pytest
from httpx import AsyncClient
from app.main import app
from uuid import uuid4
from datetime import datetime, timezone
from app.models.user_model import User, UserRole
from app.utils.nickname_gen import generate_nickname
from app.utils.security import hash_password
from sqlalchemy import select, func
from app.services.user_service import UserService
from app.services.jwt_service import decode_token  # Import your FastAPI app

# Example of a test function using the async_client fixture
@pytest.mark.asyncio
async def test_create_user_access_denied(async_client, user_token, email_service):
    headers = {"Authorization": f"Bearer {user_token}"}
    # Define user data for the test
    user_data = {
        "nickname": generate_nickname(),
        "email": "test@example.com",
        "password": "sS#fdasrongPassword123!",
    }
    # Send a POST request to create a user
    response = await async_client.post("/users/", json=user_data, headers=headers)
    # Asserts
    assert response.status_code == 403

# You can similarly refactor other test functions to use the async_client fixture
@pytest.mark.asyncio
async def test_retrieve_user_access_denied(async_client, verified_user, user_token):
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.get(f"/users/{verified_user.id}", headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_retrieve_user_access_allowed(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["id"] == str(admin_user.id)

@pytest.mark.asyncio
async def test_update_user_email_access_denied(async_client, verified_user, user_token):
    updated_data = {"email": f"updated_{verified_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.put(f"/users/{verified_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_update_user_email_access_allowed(async_client, admin_user, admin_token):
    updated_data = {"email": f"updated_{admin_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == updated_data["email"]


@pytest.mark.asyncio
async def test_delete_user(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{admin_user.id}", headers=headers)
    assert delete_response.status_code == 204
    # Verify the user is deleted
    fetch_response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert fetch_response.status_code == 404

@pytest.mark.asyncio
async def test_create_user_duplicate_email(async_client, verified_user):
    user_data = {
        "email": verified_user.email,
        "password": "AnotherPassword123!",
        "role": UserRole.ADMIN.name
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 400
    assert "Email already exists" in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_create_user_invalid_email(async_client):
    user_data = {
        "email": "notanemail",
        "password": "ValidPassword123!",
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 422

import pytest
from app.services.jwt_service import decode_token
from urllib.parse import urlencode

@pytest.mark.asyncio
async def test_login_success(async_client, verified_user):
    # Attempt to login with the test user
    form_data = {
        "username": verified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    
    # Check for successful login response
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    # Use the decode_token method from jwt_service to decode the JWT
    decoded_token = decode_token(data["access_token"])
    assert decoded_token is not None, "Failed to decode token"
    assert decoded_token["role"] == "AUTHENTICATED", "The user role should be AUTHENTICATED"

@pytest.mark.asyncio
async def test_login_user_not_found(async_client):
    form_data = {
        "username": "nonexistentuser@here.edu",
        "password": "DoesNotMatter123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_login_incorrect_password(async_client, verified_user):
    form_data = {
        "username": verified_user.email,
        "password": "IncorrectPassword123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_login_unverified_user(async_client, unverified_user):
    form_data = {
        "username": unverified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_login_locked_user(async_client, locked_user):
    form_data = {
        "username": locked_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 400
    assert "Account locked due to too many failed login attempts." in response.json().get("detail", "")
@pytest.mark.asyncio
async def test_delete_user_does_not_exist(async_client, admin_token):
    non_existent_user_id = "00000000-0000-0000-0000-000000000000"  # Valid UUID format
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{non_existent_user_id}", headers=headers)
    assert delete_response.status_code == 404

@pytest.mark.asyncio
async def test_update_user_github(async_client, admin_user, admin_token):
    updated_data = {"github_profile_url": "http://www.github.com/kaw393939"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["github_profile_url"] == updated_data["github_profile_url"]

@pytest.mark.asyncio
async def test_update_user_linkedin(async_client, admin_user, admin_token):
    updated_data = {"linkedin_profile_url": "http://www.linkedin.com/kaw393939"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["linkedin_profile_url"] == updated_data["linkedin_profile_url"]

@pytest.mark.asyncio
async def test_list_users_as_admin(async_client, admin_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert 'items' in response.json()

@pytest.mark.asyncio
async def test_list_users_as_manager(async_client, manager_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {manager_token}"}
    )
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_list_users_unauthorized(async_client, user_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 403  # Forbidden, as expected for regular user


@pytest.mark.asyncio
async def test_search_requires_admin_role(async_client: AsyncClient, user_token):
    resp = await async_client.get(
        "/users/search",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert resp.status_code == 403

@pytest.mark.asyncio
async def test_search_by_nickname_partial(async_client: AsyncClient, db_session, admin_token):
    u1 = User(
        nickname="alpha_user",
        first_name="Alpha",
        last_name="balpha",
        email=f"alpha_{uuid4().hex[:8]}@example.com",
        hashed_password=hash_password("Secure*1234"),
        role=UserRole.AUTHENTICATED,
        email_verified=True,
        is_locked=False,
    )
    u2 = User(
        nickname="beta_user",
        first_name="Beta",
        last_name="theta",
        email=f"beta_{uuid4().hex[:8]}@example.com",
        hashed_password=hash_password("Secure*1234"),
        role=UserRole.AUTHENTICATED,
        email_verified=True,
        is_locked=False,
    )
    db_session.add_all([u1, u2])
    await db_session.commit()

    resp = await async_client.get(
        "/users/search",
        params={"nickname": "alpha"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert any(u["nickname"] == "alpha_user" for u in data)
    assert all(u["nickname"] != "beta_user" for u in data)

@pytest.mark.asyncio
async def test_search_by_email_partial(async_client: AsyncClient, db_session, admin_token):
    u1 = User(
        nickname=f"nick_{uuid4().hex[:8]}",
        first_name="fifyfofum",
        last_name="gaint",
        email=f"beans_{uuid4().hex[:8]}@test.com",
        hashed_password=hash_password("Secure*1234"),
        role=UserRole.AUTHENTICATED,
        email_verified=True,
        is_locked=False,
    )
    u2 = User(
        nickname=f"nick_{uuid4().hex[:8]}",
        first_name="Kitty",
        last_name="cat",
        email=f"tuna_{uuid4().hex[:8]}@other.com",
        hashed_password=hash_password("Secure*1234"),
        role=UserRole.AUTHENTICATED,
        email_verified=True,
        is_locked=False,
    )
    db_session.add_all([u1, u2])
    await db_session.commit()

    resp = await async_client.get(
        "/users/search",
        params={"email": "@test.com"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) >= 1
    assert all("@test.com" in u["email"] for u in data)

@pytest.mark.asyncio
async def test_search_by_role(async_client: AsyncClient, db_session, admin_token):
    manager = User(
        nickname=f"mgr_{uuid4().hex[:8]}",
        first_name="Anger",
        last_name="managment",
        email=f"manager_{uuid4().hex[:8]}@example.com",
        hashed_password=hash_password("Secure*1234"),
        role=UserRole.MANAGER,
        email_verified=True,
        is_locked=False,
    )
    regular = User(
        nickname=f"user_{uuid4().hex[:8]}",
        first_name="Chill",
        last_name="guy",
        email=f"guy_{uuid4().hex[:8]}@example.com",
        hashed_password=hash_password("Secure*1234"),
        role=UserRole.AUTHENTICATED,
        email_verified=True,
        is_locked=False,
    )
    db_session.add_all([manager, regular])
    await db_session.commit()

    resp = await async_client.get(
        "/users/search",
        params={"role": "MANAGER"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert all(u["role"] == "MANAGER" for u in data)

@pytest.mark.asyncio
async def test_search_is_locked_and_email_verified(async_client: AsyncClient, db_session, admin_token):
    locked = User(
        nickname=f"lock_{uuid4().hex[:8]}",
        first_name="Dexter",
        last_name="Morgan",
        email=f"bayharbourbutcher_{uuid4().hex[:8]}@example.com",
        hashed_password=hash_password("Secure*1234"),
        role=UserRole.AUTHENTICATED,
        email_verified=True,
        is_locked=True,
    )
    unverified = User(
        nickname=f"unver_{uuid4().hex[:8]}",
        first_name="James",
        last_name="Doakes",
        email=f"james_{uuid4().hex[:8]}@example.com",
        hashed_password=hash_password("Secure*1234"),
        role=UserRole.AUTHENTICATED,
        email_verified=False,
        is_locked=False,
    )
    db_session.add_all([locked, unverified])
    await db_session.commit()

    resp_locked = await async_client.get(
        "/users/search",
        params={"is_locked": True},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert resp_locked.status_code == 200
    assert any(u["email"] == locked.email for u in resp_locked.json())

    resp_unverified = await async_client.get(
        "/users/search",
        params={"email_verified": False},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert resp_unverified.status_code == 200
    assert any(u["email"] == unverified.email for u in resp_unverified.json())

@pytest.mark.asyncio
async def test_search_created_date_range(async_client: AsyncClient, db_session, admin_token):
    older = User(
        nickname=f"old_{uuid4().hex[:8]}",
        first_name="freebo",
        last_name="Timer",
        email=f"old_{uuid4().hex[:8]}@example.com",
        hashed_password=hash_password("Secure*1234"),
        role=UserRole.AUTHENTICATED,
        email_verified=True,
        is_locked=False,
    )
    newer = User(
        nickname=f"new_{uuid4().hex[:8]}",
        first_name="New",
        last_name="Timer",
        email=f"new_{uuid4().hex[:8]}@example.com",
        hashed_password=hash_password("Secure*1234"),
        role=UserRole.AUTHENTICATED,
        email_verified=True,
        is_locked=False,
    )
    db_session.add_all([older, newer])
    await db_session.commit()

    older.created_at = datetime(2024, 1, 1, tzinfo=timezone.utc)
    newer.created_at = datetime(2025, 1, 1, tzinfo=timezone.utc)
    db_session.add_all([older, newer])
    await db_session.commit()

    resp = await async_client.get(
        "/users/search",
        params={"created_from": datetime(2024, 6, 1, tzinfo=timezone.utc).isoformat()},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert resp.status_code == 200
    emails = [u["email"] for u in resp.json()]
    assert newer.email in emails
    assert older.email not in emails

    resp2 = await async_client.get(
        "/users/search",
        params={"created_to": datetime(2024, 6, 1, tzinfo=timezone.utc).isoformat()},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert resp2.status_code == 200
    emails2 = [u["email"] for u in resp2.json()]
    assert older.email in emails2
    assert newer.email not in emails2

ENDPOINTS = [("/register/", False), ("/users/", True)]

@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint,needs_admin", ENDPOINTS)
async def test_reject_blank_password(async_client: AsyncClient, db_session, admin_token, endpoint, needs_admin):
    email = f"blank_{uuid4().hex[:8]}@example.com"
    headers = {"Authorization": f"Bearer {admin_token}"} if needs_admin else {}
    resp = await async_client.post(endpoint, json={"email": email, "password": ""}, headers=headers)
    assert resp.status_code == 422
    count = await db_session.execute(select(func.count()).select_from(User).where(User.email == email))
    assert (count.scalar() or 0) == 0

@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint,needs_admin", ENDPOINTS)
async def test_reject_whitespace_password(async_client: AsyncClient, db_session, admin_token, endpoint, needs_admin):
    email = f"space_{uuid4().hex[:8]}@example.com"
    headers = {"Authorization": f"Bearer {admin_token}"} if needs_admin else {}
    resp = await async_client.post(endpoint, json={"email": email, "password": "   "}, headers=headers)
    assert resp.status_code == 422
    count = await db_session.execute(select(func.count()).select_from(User).where(User.email == email))
    assert (count.scalar() or 0) == 0

@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint,needs_admin", ENDPOINTS)
async def test_reject_too_short_password(async_client: AsyncClient, db_session, admin_token, endpoint, needs_admin):
    email = f"short_{uuid4().hex[:8]}@example.com"
    headers = {"Authorization": f"Bearer {admin_token}"} if needs_admin else {}
    resp = await async_client.post(endpoint, json={"email": email, "password": "1234567"}, headers=headers)
    assert resp.status_code == 422
    count = await db_session.execute(select(func.count()).select_from(User).where(User.email == email))
    assert (count.scalar() or 0) == 0

@pytest.mark.asyncio
async def test_create_first_user_is_admin_has_token_and_email_sent(db_session, email_service):
    # ensure a clean slate for the mock
    email_service.send_verification_email.reset_mock()

    user = await UserService.create(
        db_session,
        {"email": f"first_{uuid4().hex[:8]}@example.com", "password": "Secure*1234"},
        email_service,
    )

    assert user.role == UserRole.ADMIN

    assert isinstance(user.verification_token, str) and len(user.verification_token) > 0

    email_service.send_verification_email.assert_awaited_once()
    args, kwargs = email_service.send_verification_email.await_args
    assert args[0].id == user.id


@pytest.mark.asyncio
async def test_create_non_admin_sets_token_and_sends_email(db_session, email_service):

    await UserService.create(db_session, {
        "email": f"seed_{uuid4().hex[:8]}@example.com",
        "password": "Secure*1234"
    }, email_service)
    email_service.send_verification_email.reset_mock()

    user = await UserService.create(db_session, {
        "email": f"user_{uuid4().hex[:8]}@example.com",
        "password": "Secure*1234"
    }, email_service)

    assert user.role != UserRole.ADMIN
    assert user.email_verified is False
    assert user.verification_token is not None and len(user.verification_token) > 0
    email_service.send_verification_email.assert_awaited_once()

    args, kwargs = email_service.send_verification_email.await_args
    assert args[0].id == user.id