import os
import json
import traceback
import uuid
import time
import secrets
from urllib.parse import urlparse, unquote
from flask import Flask, render_template, session, redirect, request
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash, check_password_hash
from supabase import create_client, Client
from dotenv import load_dotenv
from pywebpush import webpush, WebPushException
from flask import send_from_directory, jsonify

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")
VAPID_PUBLIC_KEY = os.getenv("VAPID_PUBLIC_KEY")
VAPID_PRIVATE_KEY = os.getenv("VAPID_PRIVATE_KEY")
VAPID_SUBJECT = os.getenv("VAPID_SUBJECT", "mailto:admin@example.com")

if not SUPABASE_URL or not SUPABASE_ANON_KEY:
    raise RuntimeError(
        "Missing Supabase config. Set SUPABASE_URL and SUPABASE_ANON_KEY environment variables."
    )
if not VAPID_PUBLIC_KEY or not VAPID_PRIVATE_KEY:
    raise RuntimeError(
        "Missing VAPID keys. Set VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY environment variables."
    )
if not app.secret_key:
    raise RuntimeError(
        "Missing FLASK_SECRET_KEY environment variable."
    )

supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
LOGIN_RATE_LIMIT_MAX_ATTEMPTS = 5
LOGIN_RATE_LIMIT_WINDOW_SECONDS = 15 * 60
LOGIN_RATE_LIMIT_BLOCK_SECONDS = 15 * 60
_login_attempts = {}
_csrf_unsafe_methods = {"POST", "PUT", "PATCH", "DELETE"}


@app.context_processor
def inject_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return {"csrf_token": token}


@app.before_request
def enforce_session_version():
    if not session.get("logged_in"):
        return
    user_id = session.get("user_id")
    if not user_id:
        session.clear()
        return redirect("/login/")
    try:
        result = (
            supabase.table("users")
            .select("session_version")
            .eq("id", user_id)
            .limit(1)
            .execute()
        )
        if not result.data:
            session.clear()
            return redirect("/login/")
        current_version = result.data[0].get("session_version") or 0
        if session.get("session_version") != current_version:
            session.clear()
            return redirect("/login/")
    except Exception:
        _log_exception("session-version-check")
        session.clear()
        return redirect("/login/")


@app.before_request
def csrf_protect():
    if request.method not in _csrf_unsafe_methods:
        return
    token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    session_token = session.get("csrf_token")
    if not session_token or not token or token != session_token:
        if request.is_json:
            return jsonify({"error": "invalid_csrf_token"}), 400
        return render_template(
            "error.html",
            error="Invalid or missing security token. Please refresh and try again.",
        ), 400


@app.route("/sw.js")
def service_worker():
    return send_from_directory("static", "sw.js")


@app.route("/push/vapid_public_key")
def push_vapid_public_key():
    return jsonify({"publicKey": VAPID_PUBLIC_KEY})


@app.route("/push/subscribe", methods=["POST"])
def push_subscribe():
    try:
        subscription = request.get_json()
        if not subscription:
            return jsonify({"error": "Missing subscription"}), 400

        endpoint = subscription.get("endpoint")
        if not endpoint:
            return jsonify({"error": "Missing endpoint"}), 400

        # Upsert by endpoint
        existing = (
            supabase.table("push_subscriptions")
            .select("id")
            .eq("endpoint", endpoint)
            .limit(1)
            .execute()
        )
        if existing.data:
            supabase.table("push_subscriptions").update(
                {"subscription": subscription}
            ).eq("endpoint", endpoint).execute()
        else:
            supabase.table("push_subscriptions").insert(
                {
                    "endpoint": endpoint,
                    "subscription": subscription,
                    "user_id": session.get("user_id"),
                }
            ).execute()

        return jsonify({"status": "subscribed"})
    except Exception:
        _log_exception("push-subscribe")
        return jsonify({"error": "subscription_failed"}), 500


@app.route("/push/unsubscribe", methods=["POST"])
def push_unsubscribe():
    try:
        data = request.get_json() or {}
        endpoint = data.get("endpoint")
        if endpoint:
            supabase.table("push_subscriptions").delete().eq("endpoint", endpoint).execute()
        return jsonify({"status": "unsubscribed"})
    except Exception:
        _log_exception("push-unsubscribe")
        return jsonify({"error": "unsubscribe_failed"}), 500


def _internet_error_message():
    return "Please check your internet connection and try again."


def _log_exception(context: str):
    print(f"[SUPABASE ERROR] {context}", flush=True)
    traceback.print_exc()


def _is_password_hash(password_value: str):
    if not password_value:
        return False
    known_prefixes = ("scrypt:", "pbkdf2:", "argon2:", "$2a$", "$2b$", "$2y$")
    return password_value.startswith(known_prefixes)


def _verify_password(stored_password: str, candidate_password: str):
    if not stored_password or not candidate_password:
        return False
    if _is_password_hash(stored_password):
        try:
            return check_password_hash(stored_password, candidate_password)
        except Exception:
            return False
    return stored_password == candidate_password


def _client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _prune_attempt_window(entry: dict, now_ts: float):
    fails = entry.get("fails", [])
    entry["fails"] = [ts for ts in fails if now_ts - ts <= LOGIN_RATE_LIMIT_WINDOW_SECONDS]


def _is_login_rate_limited(ip: str):
    now_ts = time.time()
    entry = _login_attempts.get(ip)
    if not entry:
        return False, 0
    blocked_until = entry.get("blocked_until") or 0
    if blocked_until > now_ts:
        return True, int(blocked_until - now_ts)
    _prune_attempt_window(entry, now_ts)
    return False, 0


def _register_login_failure(ip: str):
    now_ts = time.time()
    entry = _login_attempts.setdefault(ip, {"fails": [], "blocked_until": 0})
    _prune_attempt_window(entry, now_ts)
    entry["fails"].append(now_ts)
    if len(entry["fails"]) >= LOGIN_RATE_LIMIT_MAX_ATTEMPTS:
        entry["blocked_until"] = now_ts + LOGIN_RATE_LIMIT_BLOCK_SECONDS


def _clear_login_failures(ip: str):
    _login_attempts.pop(ip, None)


def _send_push_to_all(payload: dict):
    try:
        subs = (
            supabase.table("push_subscriptions")
            .select("id,subscription")
            .execute()
        )
        for row in subs.data or []:
            sub = row.get("subscription")
            if not sub:
                continue
            try:
                webpush(
                    subscription_info=sub,
                    data=json.dumps(payload),
                    vapid_private_key=VAPID_PRIVATE_KEY,
                    vapid_claims={"sub": VAPID_SUBJECT},
                )
            except WebPushException:
                # Remove dead subscriptions (e.g., 410/404)
                supabase.table("push_subscriptions").delete().eq(
                    "id", row.get("id")
                ).execute()
    except Exception:
        _log_exception("push-send")


def _send_push_to_admins(payload: dict):
    try:
        admins = supabase.table("users").select("id").eq("role", "admin").execute()
        admin_ids = [row.get("id") for row in (admins.data or []) if row.get("id")]
        if not admin_ids:
            return
        subs = (
            supabase.table("push_subscriptions")
            .select("id,subscription,user_id")
            .in_("user_id", admin_ids)
            .execute()
        )
        for row in subs.data or []:
            sub = row.get("subscription")
            if not sub:
                continue
            try:
                webpush(
                    subscription_info=sub,
                    data=json.dumps(payload),
                    vapid_private_key=VAPID_PRIVATE_KEY,
                    vapid_claims={"sub": VAPID_SUBJECT},
                )
            except WebPushException:
                supabase.table("push_subscriptions").delete().eq(
                    "id", row.get("id")
                ).execute()
    except Exception:
        _log_exception("push-send-admins")


def _get_admin_email():
    user_id = session.get("user_id")
    if not user_id:
        return ""
    try:
        result = (
            supabase.table("users")
            .select("email")
            .eq("id", user_id)
            .limit(1)
            .execute()
        )
        if result.data:
            return result.data[0].get("email") or ""
    except Exception:
        _log_exception("get-admin-email")
    return ""


def _storage_path_from_public_url(url: str):
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        path = unquote(parsed.path or "")
    except Exception:
        path = url

    markers = [
        "/storage/v1/object/public/images/",
        "/storage/v1/object/sign/images/",
        "/images/",
    ]
    for marker in markers:
        if marker in path:
            return path.split(marker, 1)[1]
    return ""


def _normalize_image_entries(image_urls):
    if not image_urls:
        return []
    normalized = []
    for item in image_urls:
        if isinstance(item, dict):
            url = item.get("url")
            path = item.get("path") or _storage_path_from_public_url(url or "")
            if url:
                normalized.append({"url": url, "path": path})
        elif isinstance(item, str):
            normalized.append({"url": item, "path": _storage_path_from_public_url(item)})
    return normalized


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    if isinstance(error, HTTPException):
        return error
    _log_exception("unhandled-error")
    return render_template("error.html", error=_internet_error_message()), 500


@app.route("/")
def landing_page():
    return render_template("landing_page.html")


@app.route("/admin/")
def admin():
    if not session.get("logged_in") or session.get("role") != "admin":
        return redirect("/login/")
    return render_template("admin.html")


@app.route("/login/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = _client_ip()
        limited, retry_after = _is_login_rate_limited(ip)
        if limited:
            mins = max(1, retry_after // 60)
            return render_template(
                "login.html",
                error=f"Too many login attempts. Try again in about {mins} minute(s).",
            )

        email = request.form.get("login_email")
        password = request.form.get("login_password")

        if not email or not password:
            return render_template("login.html", error="Email and password required")

        try:
            result = (
                supabase.table("users")
                .select("id,name,email,role,session_version,password")
                .eq("email", email)
                .limit(1)
                .execute()
            )
        except Exception:
            _log_exception("login")
            return render_template("login.html", error=_internet_error_message())

        if result.data and _verify_password(result.data[0].get("password"), password):
            user_row = result.data[0]
            stored_password = user_row.get("password") or ""

            # One-time migration path for legacy plaintext passwords.
            if not _is_password_hash(stored_password):
                try:
                    supabase.table("users").update(
                        {"password": generate_password_hash(password)}
                    ).eq("id", user_row.get("id")).execute()
                except Exception:
                    _log_exception("login-migrate-password")

            session["logged_in"] = True
            session["user_id"] = user_row.get("id")
            session["name"] = user_row.get("name")
            session["email"] = user_row.get("email")
            session["role"] = user_row.get("role") or "user"
            session["session_version"] = user_row.get("session_version") or 0
            _clear_login_failures(ip)
            if session["role"] == "admin":
                return redirect("/admin/")
            return redirect("/user/")

        _register_login_failure(ip)
        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


@app.route("/signup/", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("sign_name")
        email = request.form.get("sign_email")
        password = request.form.get("sign_password")
        if not name or not email or not password:
            return render_template("signup.html", error="All fields are required")

        try:
            existing = (
                supabase.table("users")
                .select("id")
                .eq("email", email)
                .limit(1)
                .execute()
            )
        except Exception:
            _log_exception("signup-check-existing")
            return render_template("signup.html", error=_internet_error_message())
        if existing.data:
            return render_template("signup.html", error="Email already registered")

        try:
            insert_result = (
                supabase.table("users")
                .insert(
                    {
                        "name": name,
                        "email": email,
                        "password": generate_password_hash(password),
                        "session_version": 1,
                    }
                )
                .execute()
            )
        except Exception:
            _log_exception("signup-insert")
            return render_template("signup.html", error=_internet_error_message())

        if not insert_result.data:
            return render_template("signup.html", error="Signup failed")

        return redirect("/login/")

    return render_template("signup.html")


@app.route("/user/")
def user():
    if not session.get("logged_in"):
        return redirect("/login/")
    fb_success = session.pop("fb_success", None)
    if not session.get("fb_token"):
        session["fb_token"] = uuid.uuid4().hex
    return render_template("user.html", fb_success=fb_success, fb_token=session["fb_token"])


@app.route("/feedback/", methods=["POST"])
def feedback():
    token = request.form.get("fb_token")
    if not token or token != session.get("fb_token"):
        return redirect("/user/")
    name = request.form.get("fb_name")
    email = request.form.get("fb_email")
    feedback_text = request.form.get("fb_feedback")

    if not name or not email or not feedback_text:
        return render_template("user.html", fb_error="All fields are required")

    try:
        supabase.table("feedback").insert(
            {"name": name, "email": email, "feedback": feedback_text}
        ).execute()
        _send_push_to_admins(
            {
                "title": "B20X - New Feedback",
                "body": f"{name} ({email}): {feedback_text}",
                "url": "http://127.0.0.1:5000/admin/",
            }
        )
        session["fb_success"] = "Thank you for your feedback!"
        session["fb_token"] = uuid.uuid4().hex
        return redirect("/user/")
    except Exception:
        _log_exception("feedback-insert")
        return render_template("user.html", fb_error=_internet_error_message())


@app.route("/feedbacks/")
def feedbacks():
    if not session.get("logged_in") or session.get("role") != "admin":
        return redirect("/login/")
    try:
        result = (
            supabase.table("feedback")
            .select("id,name,email,feedback,created_at")
            .order("created_at", desc=True)
            .execute()
        )
        feedback_rows = result.data or []
        return render_template("feedbacks.html", feedback_rows=feedback_rows)
    except Exception:
        _log_exception("feedbacks-fetch")
        return render_template(
            "feedbacks.html", feedback_rows=[], error=_internet_error_message()
        )


@app.route("/feedbacks/delete", methods=["POST"])
def feedbacks_delete():
    if not session.get("logged_in") or session.get("role") != "admin":
        return redirect("/login/")
    feedback_id = request.form.get("feedback_id")
    if not feedback_id:
        return redirect("/feedbacks/")
    try:
        supabase.table("feedback").delete().eq("id", feedback_id).execute()
    except Exception:
        _log_exception("feedbacks-delete")
    return redirect("/feedbacks/")


@app.route("/users_details/")
def users_details():
    if not session.get("logged_in") or session.get("role") != "admin":
        return redirect("/login/")

    try:
        result = supabase.table("users").select("id,name,email,role").execute()
        users = result.data or []
        return render_template("users_details.html", users=users)
    except Exception:
        _log_exception("users_details")
        return render_template("users_details.html", users=[], error=_internet_error_message())


@app.route("/update_details/", methods=["GET", "POST"])
def update_details():
    if not session.get("logged_in") or session.get("role") != "admin":
        return redirect("/login/")

    message = None
    error = None

    if request.method == "POST":
        action = request.form.get("action") or "update"
        user_id = request.form.get("user_id")
        name = request.form.get("name")
        email = request.form.get("email")
        role = request.form.get("role")
        password = request.form.get("password")

        if not user_id:
            error = "User is required"
        else:
            if action == "delete":
                try:
                    delete_result = (
                        supabase.table("users").delete().eq("id", user_id).execute()
                    )
                    if delete_result.data is not None:
                        message = "User deleted"
                    else:
                        error = "Delete failed"
                except Exception:
                    _log_exception("update_details-update")
                    error = _internet_error_message()
            else:
                update_payload = {}
                if name:
                    update_payload["name"] = name
                if email:
                    update_payload["email"] = email
                if role:
                    update_payload["role"] = role
                if password:
                    update_payload["password"] = generate_password_hash(password)

                if not update_payload:
                    error = "Nothing to update"
                else:
                    try:
                        # If role or password actually changed, bump session_version to force logout
                        if "role" in update_payload or "password" in update_payload:
                            current = (
                                supabase.table("users")
                                .select("role,password,session_version")
                                .eq("id", user_id)
                                .limit(1)
                                .execute()
                            )
                            current_row = current.data[0] if current.data else {}
                            current_version = current_row.get("session_version") or 0
                            should_bump = False
                            if "role" in update_payload and update_payload["role"] != current_row.get("role"):
                                should_bump = True
                            # Any submitted password reset should force re-login.
                            if password:
                                should_bump = True
                            if should_bump:
                                update_payload["session_version"] = current_version + 1

                        update_result = (
                            supabase.table("users")
                            .update(update_payload)
                            .eq("id", user_id)
                            .execute()
                        )
                        if update_result.data:
                            message = "User updated"
                        else:
                            error = "Update failed"
                    except Exception:
                        error = _internet_error_message()

    try:
        users_result = supabase.table("users").select("id,name,email,role").execute()
        users = users_result.data or []
    except Exception:
        _log_exception("update_details-fetch-users")
        users = []
        if not error:
            error = _internet_error_message()
    return render_template(
        "update_details.html", users=users, message=message, error=error
    )


@app.route("/info/", methods=["GET", "POST"])
def info():
    is_admin = session.get("logged_in") and session.get("role") == "admin"
    message = None
    error = None
    error_detail = None

    if request.method == "POST":
        if not is_admin:
            return redirect("/login/")

        action = request.form.get("action") or "add"
        info_id = request.form.get("info_id")

        try:
            if action == "add_empty":
                supabase.table("info").insert({}).execute()
                message = "New info row added"
            elif action == "delete" and info_id:
                # remove all images from storage before deleting row
                current_row = (
                    supabase.table("info")
                    .select("image_urls")
                    .eq("id", info_id)
                    .limit(1)
                    .execute()
                )
                existing = []
                if current_row.data and current_row.data[0].get("image_urls"):
                    existing = _normalize_image_entries(current_row.data[0]["image_urls"])
                storage_paths = []
                for entry in existing:
                    path = entry.get("path")
                    if path:
                        storage_paths.append(path)
                if storage_paths:
                    try:
                        supabase.storage.from_("images").remove(storage_paths)
                    except Exception:
                        _log_exception("storage-remove-row-images")
                supabase.table("info").delete().eq("id", info_id).execute()
                message = "Info deleted"
            elif action == "remove_image" and info_id:
                image_url = request.form.get("image_url")
                image_path = request.form.get("image_path")
                if image_url or image_path:
                    current_row = (
                        supabase.table("info")
                        .select("image_urls")
                        .eq("id", info_id)
                        .limit(1)
                        .execute()
                    )
                    existing = []
                    if current_row.data and current_row.data[0].get("image_urls"):
                        existing = _normalize_image_entries(current_row.data[0]["image_urls"])
                    new_entries = []
                    for entry in existing:
                        if image_path and entry.get("path") == image_path:
                            continue
                        if image_url and entry.get("url") == image_url:
                            continue
                        new_entries.append(entry)
                    # Remove from storage bucket as well
                    storage_path = image_path or _storage_path_from_public_url(image_url or "")
                    if storage_path:
                        try:
                            supabase.storage.from_("images").remove([storage_path])
                        except Exception:
                            _log_exception("storage-remove-image")
                    supabase.table("info").update({"image_urls": new_entries}).eq(
                        "id", info_id
                    ).execute()
                    message = "Image removed"
                else:
                    error = "Image not specified"
            elif action == "remove_extra" and info_id:
                remove_key = request.form.get("remove_key")
                if remove_key:
                    current_row = (
                        supabase.table("info")
                        .select("extra")
                        .eq("id", info_id)
                        .limit(1)
                        .execute()
                    )
                    existing_extra = {}
                    if current_row.data and current_row.data[0].get("extra"):
                        existing_extra = current_row.data[0]["extra"]
                    if remove_key in existing_extra:
                        existing_extra.pop(remove_key, None)
                        supabase.table("info").update({"extra": existing_extra}).eq(
                            "id", info_id
                        ).execute()
                    message = "Field removed"
                else:
                    error = "Field not specified"
            elif action == "update" and info_id:
                before_row = (
                    supabase.table("info")
                    .select("title,content,extra,image_urls")
                    .eq("id", info_id)
                    .limit(1)
                    .execute()
                )
                before = before_row.data[0] if before_row.data else {}
                before_empty = not (
                    (before.get("title") or "")
                    or (before.get("content") or "")
                    or (before.get("image_urls") or [])
                    or (before.get("extra") or {})
                )
                title = request.form.get("title")
                content = request.form.get("content")
                extra_keys = request.form.getlist("extra_key")
                extra_values = request.form.getlist("extra_value")
                update_payload = {}
                if title is not None:
                    update_payload["title"] = title
                if content is not None:
                    update_payload["content"] = content
                extra_data = {}
                for key, value in zip(extra_keys, extra_values):
                    key = (key or "").strip()
                    if not key:
                        continue
                    extra_data[key] = value
                update_payload["extra"] = extra_data

                # Handle image uploads (optional, multiple)
                images = request.files.getlist("images")
                if images:
                    current_row = (
                        supabase.table("info")
                        .select("image_urls")
                        .eq("id", info_id)
                        .limit(1)
                        .execute()
                    )
                    existing = []
                    if current_row.data and current_row.data[0].get("image_urls"):
                        existing = _normalize_image_entries(current_row.data[0]["image_urls"])

                    uploaded_entries = []
                    for image in images:
                        if not image or not image.filename:
                            continue
                        _, ext = os.path.splitext(image.filename)
                        safe_ext = ext if ext else ""
                        path = f"{info_id}/{uuid.uuid4().hex}{safe_ext}"
                        content_type = image.mimetype or "application/octet-stream"
                        supabase.storage.from_("images").upload(
                            path,
                            image.read(),
                            {"content-type": content_type},
                        )
                        public_url = supabase.storage.from_("images").get_public_url(path)
                        uploaded_entries.append({"url": public_url, "path": path})

                    update_payload["image_urls"] = existing + uploaded_entries

                if update_payload:
                    supabase.table("info").update(update_payload).eq("id", info_id).execute()
                    message = "Info updated"
                    title_text = f"B20X - {title or 'Info updated'}"
                    admin_email = _get_admin_email()
                    body_parts = []
                    if content:
                        body_parts.append(content)
                    if admin_email:
                        body_parts.append(f"By: {admin_email}")
                    body_text = " | ".join(body_parts)
                    _send_push_to_all(
                        {
                            "title": title_text,
                            "body": body_text,
                            "url": "http://127.0.0.1:5000/info/",
                        }
                    )
                else:
                    if not error:
                        error = "Nothing to update"
            else:
                error = "Invalid action"
        except Exception as exc:
            _log_exception("info-action")
            error = _internet_error_message()
            if is_admin:
                error_detail = str(exc)

        if message and not error:
            return redirect("/info/")

    try:
        result = (
            supabase.table("info")
            .select("id,title,content,extra,image_urls")
            .order("id", desc=False)
            .execute()
        )
        info_rows = result.data or []
    except Exception as exc:
        _log_exception("info-fetch")
        info_rows = []
        if not error:
            error = _internet_error_message()
        if is_admin:
            error_detail = str(exc)

    return render_template(
        "info.html",
        info_rows=info_rows,
        is_admin=is_admin,
        message=message,
        error=error,
        error_detail=error_detail,
        logged_in=bool(session.get("logged_in")),
    )


@app.route("/logout/")
def logout():
    session.clear()
    return redirect("/")






if __name__ == "__main__":
    app.run()
