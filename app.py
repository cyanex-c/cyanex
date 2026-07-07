"""
安全版用户管理系统 - 修复了原版所有安全漏洞
"""
import os
import re
import time
import secrets
from functools import wraps
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request, redirect, session,
    jsonify, make_response, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf


app = Flask(__name__)

# ============================================================
# 安全配置
# ============================================================
app.secret_key = os.environ.get(
    "SECRET_KEY",
    secrets.token_hex(32)
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    SESSION_REFRESH_EACH_REQUEST=True,
    WTF_CSRF_ENABLED=True,
    DEBUG=False,
)

# ============================================================
# 安全扩展
# ============================================================
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)
csrf = CSRFProtect(app)


# ============================================================
# 密码哈希存储的用户数据库
# ============================================================
def _hash(password):
    return generate_password_hash(password)


USERS = {
    "admin": {
        "username": "admin",
        "password_hash": _hash("Admin@123456"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
        "failed_attempts": 0,
        "locked_until": None,
        "created_at": "2025-01-01",
    },
    "alice": {
        "username": "alice",
        "password_hash": _hash("Alice@2025@Secure"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
        "failed_attempts": 0,
        "locked_until": None,
        "created_at": "2025-06-01",
    },
}

# ============================================================
# 安全辅助函数
# ============================================================
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 15
PASSWORD_MIN_LENGTH = 8
PASSWORD_REGEX = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_#])[A-Za-z\d@$!%*?&_#]{8,}$"
)


def sanitize_input(text):
    if not isinstance(text, str):
        return ""
    dangerous = ["<", ">", '"', "'", "&", "\\", ";", "`", "$", "(", ")"]
    for char in dangerous:
        text = text.replace(char, "")
    return text.strip()


def is_account_locked(user):
    if user.get("locked_until"):
        if datetime.now() < user["locked_until"]:
            remaining = (user["locked_until"] - datetime.now()).seconds
            return True, remaining
        else:
            user["locked_until"] = None
            user["failed_attempts"] = 0
    return False, 0


def record_failed_attempt(username):
    if username in USERS:
        user = USERS[username]
        user["failed_attempts"] = user.get("failed_attempts", 0) + 1
        if user["failed_attempts"] >= MAX_LOGIN_ATTEMPTS:
            user["locked_until"] = datetime.now() + timedelta(minutes=LOCKOUT_DURATION)
            return True
    return False


def reset_login_attempts(username):
    if username in USERS:
        USERS[username]["failed_attempts"] = 0
        USERS[username]["locked_until"] = None


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            return redirect("/login?next=" + request.path)
        if session.get("username") not in USERS:
            session.clear()
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        username = session.get("username")
        if not username or username not in USERS:
            return redirect("/login")
        if USERS[username]["role"] != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.after_request
def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "form-action 'self'"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    return response


# ============================================================
# 路由：首页
# ============================================================
@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user = USERS[username]
        user_info = {
            "username": user["username"],
            "role": user["role"],
            "email": user["email"],
            "phone": user["phone"],
            "balance": user["balance"],
            "created_at": user.get("created_at", "未知"),
        }
    return render_template("index.html", username=username, user=user_info)


# ============================================================
# 路由：登录
# ============================================================
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if "username" in session:
        return redirect("/")

    error = None
    remaining_attempts = None

    if request.method == "POST":
        username = sanitize_input(request.form.get("username", ""))
        password = request.form.get("password", "")

        if not username or not password:
            error = "用户名和密码不能为空"
            return render_template("login.html", error=error, csrf_token=generate_csrf()), 400

        user_exists = username in USERS

        if not user_exists:
            error = "用户名或密码错误"
            time.sleep(0.1)
            return render_template("login.html", error=error, csrf_token=generate_csrf()), 401

        user = USERS[username]

        locked, remaining = is_account_locked(user)
        if locked:
            error = f"账户已被锁定，请在 {remaining} 秒后重试"
            return render_template("login.html", error=error, csrf_token=generate_csrf()), 429

        if check_password_hash(user["password_hash"], password):
            reset_login_attempts(username)
            session.clear()
            session.permanent = True
            session["username"] = username
            session["login_time"] = datetime.now().isoformat()
            session["ip_address"] = request.remote_addr

            user_info = {
                "username": user["username"],
                "role": user["role"],
                "email": user["email"],
                "phone": user["phone"],
                "balance": user["balance"],
            }
            return render_template("index.html", username=username, user=user_info)
        else:
            just_locked = record_failed_attempt(username)
            attempts_left = MAX_LOGIN_ATTEMPTS - USERS[username].get("failed_attempts", 0)
            if just_locked:
                error = f"登录失败次数过多，账户已被锁定 {LOCKOUT_DURATION} 分钟"
                remaining_attempts = 0
            else:
                error = "用户名或密码错误"
                remaining_attempts = max(0, attempts_left)

    return render_template(
        "login.html",
        error=error,
        remaining_attempts=remaining_attempts,
        csrf_token=generate_csrf(),
    )


# ============================================================
# 路由：登出
# ============================================================
@app.route("/logout")
def logout():
    session.clear()
    resp = redirect("/login")
    resp.delete_cookie("session")
    return resp


# ============================================================
# 路由：修改密码
# ============================================================
@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    error = None
    success = None
    username = session["username"]

    if request.method == "POST":
        current_pw = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")

        if not check_password_hash(USERS[username]["password_hash"], current_pw):
            error = "当前密码错误"
        elif new_pw != confirm_pw:
            error = "两次输入的新密码不一致"
        elif len(new_pw) < PASSWORD_MIN_LENGTH:
            error = f"密码长度至少 {PASSWORD_MIN_LENGTH} 位"
        elif not PASSWORD_REGEX.match(new_pw):
            error = "密码必须包含大小写字母、数字和特殊字符"
        else:
            USERS[username]["password_hash"] = _hash(new_pw)
            success = "密码修改成功！下次登录请使用新密码。"

    return render_template(
        "change_password.html",
        error=error,
        success=success,
        csrf_token=generate_csrf(),
    )


# ============================================================
# 路由：管理员控制台
# ============================================================
@app.route("/admin/sessions")
@admin_required
def admin_sessions():
    users_status = []
    for name, info in USERS.items():
        users_status.append({
            "username": name,
            "role": info["role"],
            "failed_attempts": info.get("failed_attempts", 0),
            "locked": info.get("locked_until") is not None,
            "locked_remaining": (
                (info["locked_until"] - datetime.now()).seconds
                if info.get("locked_until") and info["locked_until"] > datetime.now()
                else 0
            ),
        })
    return render_template(
        "admin_sessions.html",
        users=users_status,
        csrf_token=generate_csrf(),
    )


@app.route("/admin/unlock/<username>", methods=["POST"])
@admin_required
def admin_unlock(username):
    if username in USERS:
        USERS[username]["locked_until"] = None
        USERS[username]["failed_attempts"] = 0
    return redirect("/admin/sessions")


# ============================================================
# 错误处理
# ============================================================
@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="访问被拒绝"), 403

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="页面未找到"), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template("error.html", code=429, message="请求过于频繁，请稍后再试"), 429

@app.errorhandler(500)
def internal_error(e):
    return render_template("error.html", code=500, message="服务器内部错误"), 500


# ============================================================
# 启动
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("  安全版用户管理系统")
    print("  监听地址: 192.168.13.128:5000")
    print("  CSRF: 已启用 | 限流: 已启用 | Session: 已加固")
    print("=" * 60)
    app.run(host="192.168.13.128", port=5000, debug=False)
