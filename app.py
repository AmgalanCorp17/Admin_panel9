import hmac
import logging
import os
import secrets

import bcrypt
import httpx
from dotenv import load_dotenv
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from postgrest.exceptions import APIError
from supabase import Client, create_client

load_dotenv()

logging.basicConfig(level=logging.INFO)
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

supabase_url = os.getenv("SUPABASE_URL", "").strip()
supabase_secret_key = os.getenv("SUPABASE_SECRET_KEY", "").strip()

if not supabase_url or not supabase_secret_key:
    raise RuntimeError("SUPABASE_URL болон SUPABASE_SECRET_KEY-г .env файлд тохируулна уу.")

if supabase_secret_key.startswith("sb_publishable_"):
    logger.warning(
        "SUPABASE_SECRET_KEY is a publishable key; use a server-side secret key for table access"
    )

supabase: Client = create_client(supabase_url, supabase_secret_key)

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


def get_csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def require_valid_csrf() -> None:
    submitted_token = request.form.get("csrf_token", "")
    stored_token = session.get("csrf_token", "")
    if not stored_token or not hmac.compare_digest(submitted_token, stored_token):
        abort(400)


@app.get("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        require_valid_csrf()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password or len(password.encode("utf-8")) > 72:
            flash("И-мэйл эсвэл нууц үг буруу байна.", "error")
            return render_template("login.html", csrf_token=get_csrf_token()), 401

        try:
            result = (
                supabase.table("users")
                .select("id,email,password_hash")
                .eq("email", email)
                .limit(1)
                .execute()
            )
        except APIError as exc:
            logger.exception("Could not look up login account in Supabase")
            if exc.code == "42501":
                flash("service_role-д public.users хүснэгтийг унших эрх олгох шаардлагатай.", "error")
            else:
                flash("Supabase users хүснэгтийн тохиргоог шалгана уу.", "error")
            return render_template("login.html", csrf_token=get_csrf_token()), 503
        except httpx.HTTPError:
            logger.exception("Could not connect to Supabase while logging in")
            flash("Supabase-тэй холбогдож чадсангүй. Хаяг болон холболтоо шалгана уу.", "error")
            return render_template("login.html", csrf_token=get_csrf_token()), 503

        user = result.data[0] if result.data else None
        if not user:
            flash("И-мэйл эсвэл нууц үг буруу байна.", "error")
            return render_template("login.html", csrf_token=get_csrf_token()), 401

        try:
            password_matches = bcrypt.checkpw(
                password.encode("utf-8"),
                user["password_hash"].encode("utf-8"),
            )
        except (KeyError, TypeError, ValueError):
            logger.exception("The stored bcrypt password hash is invalid")
            flash("И-мэйл эсвэл нууц үг буруу байна.", "error")
            return render_template("login.html", csrf_token=get_csrf_token()), 401

        if not password_matches:
            flash("И-мэйл эсвэл нууц үг буруу байна.", "error")
            return render_template("login.html", csrf_token=get_csrf_token()), 401

        session.clear()
        session["user_id"] = user["id"]
        session["email"] = user["email"]
        get_csrf_token()
        return redirect(url_for("dashboard"))

    return render_template("login.html", csrf_token=get_csrf_token())


@app.get("/dashboard")
def dashboard():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    try:
        result = (
            supabase.table("content_drafts")
            .select("id,title,content,created_at")
            .eq("status", "draft")
            .order("created_at", desc=True)
            .execute()
        )
    except APIError as exc:
        logger.exception("Could not load content drafts from Supabase")
        if exc.code == "42501":
            flash(
                "service_role-д public.content_drafts хүснэгтийг унших эрх олгох шаардлагатай.",
                "error",
            )
        else:
            flash("content_drafts хүснэгтийн тохиргоог шалгана уу.", "error")
        drafts = None
    except httpx.HTTPError:
        logger.exception("Could not connect to Supabase while loading drafts")
        flash("Нооргуудыг ачаалж чадсангүй. Supabase холболтоо шалгана уу.", "error")
        drafts = None
    else:
        drafts = result.data

    return render_template(
        "dashboard.html",
        active_page="content",
        drafts=drafts,
        email=session.get("email", ""),
        csrf_token=get_csrf_token(),
    )


@app.post("/drafts/<int:draft_id>/<decision>")
def review_draft(draft_id: int, decision: str):
    if not session.get("user_id"):
        return redirect(url_for("login"))
    require_valid_csrf()

    next_status = {"approve": "published", "reject": "rejected"}.get(decision)
    if next_status is None:
        abort(404)

    try:
        result = (
            supabase.table("content_drafts")
            .update({"status": next_status})
            .eq("id", draft_id)
            .eq("status", "draft")
            .select("id")
            .execute()
        )
    except APIError as exc:
        logger.exception("Could not update draft review status")
        if exc.code == "42501":
            flash(
                "service_role-д content_drafts хүснэгтийг унших, төлөв шинэчлэх эрх олгоно уу.",
                "error",
            )
        elif exc.code == "23514":
            flash(
                "Supabase-д rejected төлөв зөвшөөрөгдөөгүй байна. Шинэчлэлийн SQL-г эхлээд ажиллуулна уу.",
                "error",
            )
        else:
            flash("Нооргийн төлөвийг өөрчилж чадсангүй. Supabase тохиргоог шалгана уу.", "error")
        return redirect(url_for("dashboard"))
    except httpx.HTTPError:
        logger.exception("Could not connect to Supabase while reviewing a draft")
        flash("Нооргийн төлөвийг өөрчилж чадсангүй. Supabase холболтоо шалгана уу.", "error")
        return redirect(url_for("dashboard"))

    if not result.data:
        flash("Энэ ноорог аль хэдийн шийдэгдсэн эсвэл олдсонгүй.", "error")
        return redirect(url_for("dashboard"))

    if next_status == "published":
        flash("Нооргийг баталж, нийтэллээ.", "success")
    else:
        flash("Нооргоос татгалзлаа.", "success")
    return redirect(url_for("dashboard"))


@app.get("/facebook")
def facebook():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        active_page="facebook",
        email=session.get("email", ""),
        csrf_token=get_csrf_token(),
    )


@app.get("/chat")
def chat():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        active_page="chat",
        email=session.get("email", ""),
        csrf_token=get_csrf_token(),
    )


@app.get("/bookings")
def bookings():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    try:
        result = (
            supabase.table("bookings")
            .select("id,customer_name,email,booking_date,party_size,status")
            .order("booking_date")
            .execute()
        )
    except APIError as exc:
        logger.exception("Could not load bookings from Supabase")
        if exc.code == "42501":
            flash("service_role-д public.bookings хүснэгтийг унших эрх олгох шаардлагатай.", "error")
        else:
            flash("bookings хүснэгтийн тохиргоог шалгана уу.", "error")
        bookings_data = None
    except httpx.HTTPError:
        logger.exception("Could not connect to Supabase while loading bookings")
        flash("Захиалгуудыг ачаалж чадсангүй. Supabase холболтоо шалгана уу.", "error")
        bookings_data = None
    else:
        bookings_data = result.data

    return render_template(
        "dashboard.html",
        active_page="bookings",
        bookings=bookings_data,
        email=session.get("email", ""),
        csrf_token=get_csrf_token(),
    )


@app.post("/logout")
def logout():
    require_valid_csrf()
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
