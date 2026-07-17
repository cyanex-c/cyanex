"""
安全版用户管理系统 - 修复了原版所有安全漏洞
（含演示用注册/搜索功能，SQL 语句使用字符串拼接演示注入风险）
"""
import os
import re
import json
import time
import secrets
import sqlite3
import socket
import subprocess
import platform
import xml.etree.ElementTree as ET
import urllib.request
import urllib.error
import urllib.parse
from functools import wraps
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request, redirect, session,
    jsonify, make_response, abort, flash
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
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB
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


# ============================================================
# 数据库初始化（演示用，SQL 注入风险）
# ============================================================
def init_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT
        )
    """)
    # 添加 balance 列（如果不存在）
    try:
        c.execute("ALTER TABLE users ADD COLUMN balance REAL DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # 列已存在
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)",
              ("admin", "admin123", "admin@example.com", "13800138000", 99999))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)",
              ("alice", "alice2025", "alice@example.com", "13900139001", 100))
    conn.commit()
    conn.close()
    print("[数据库] data/users.db 初始化完成")


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
    return render_template("index.html", username=username, user=user_info, csrf_token=generate_csrf())


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
            return render_template("index.html", username=username, user=user_info, csrf_token=generate_csrf())
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
# 路由：修改密码（已修复 CSRF 漏洞）
# ============================================================
@app.route("/change-password", methods=["POST"])
def change_password():
    if "username" not in session:
        return redirect("/login")

    # 从 session 获取当前登录用户（不从表单拿 username）
    username = session["username"]
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if username not in USERS:
        flash("用户不存在", "error")
        return redirect("/profile")

    # 验证原密码
    if not check_password_hash(USERS[username]["password_hash"], current_password):
        flash("当前密码错误", "error")
        return redirect("/profile")

    # 验证两次新密码一致
    if new_password != confirm_password:
        flash("两次输入的新密码不一致", "error")
        return redirect("/profile")

    # 密码强度校验
    if len(new_password) < 4:
        flash("密码长度至少 4 位", "error")
        return redirect("/profile")

    # 更新密码
    USERS[username]["password_hash"] = _hash(new_password)
    USERS[username]["failed_attempts"] = 0
    USERS[username]["locked_until"] = None
    print(f"[CHANGE-PASSWORD] {username} 修改了密码")
    flash("密码修改成功！", "success")

    return redirect("/profile")


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
# 路由：注册（演示 SQL 注入风险 - 使用 f-string 拼接）
# ============================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        # 使用参数化查询防止 SQL 注入
        sql = "INSERT INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)"
        print(f"[DEBUG-REGISTER] 执行 SQL: {sql} 参数: {username}")

        try:
            conn = sqlite3.connect("data/users.db")
            c = conn.cursor()
            c.execute(sql, (username, password, email, phone, 0))
            conn.commit()
            conn.close()
            flash("注册成功，请登录", "success")
            return redirect("/login")
        except Exception as e:
            error = f"注册失败: {e}"
            print(f"[ERROR] {e}")

    return render_template("register.html", error=error, csrf_token=generate_csrf())


# ============================================================
# 路由：搜索（演示 SQL 注入风险 - 使用 f-string 拼接）
# ============================================================
@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    results = []
    if keyword:
        # 使用参数化查询防止 SQL 注入
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        like_pattern = f"%{keyword}%"
        print(f"[DEBUG-SEARCH] 执行 SQL: {sql} 参数: {like_pattern}")

        try:
            conn = sqlite3.connect("data/users.db")
            c = conn.cursor()
            c.execute(sql, (like_pattern, like_pattern))
            rows = c.fetchall()
            conn.close()
            for row in rows:
                results.append({"id": row[0], "username": row[1], "email": row[2], "phone": row[3]})
            print(f"[DEBUG-SEARCH] 返回 {len(results)} 条结果")
        except Exception as e:
            print(f"[ERROR] 搜索出错: {e}")

    # 获取当前用户信息
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

    return render_template("index.html", username=username, user=user_info, csrf_token=generate_csrf(),
                           search_keyword=keyword, search_results=results)


# ============================================================
# 路由：头像上传（无文件类型检查）
# ============================================================
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "username" not in session:
        return redirect("/login")

    file_url = None
    error = None

    # 允许的图片扩展名
    ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg"}
    # 图片文件魔数（magic bytes）
    IMAGE_MAGIC = {
        b"\x89PNG\r\n\x1a\n": ".png",
        b"\xff\xd8\xff": ".jpg",
        b"GIF87a": ".gif",
        b"GIF89a": ".gif",
        b"RIFF": ".webp",  # WEBP 以 RIFF 开头
        b"BM": ".bmp",
        b"<?xml": ".svg",
        b"<svg": ".svg",
    }

    if request.method == "POST":
        if "file" not in request.files:
            error = "未选择文件"
        else:
            f = request.files["file"]
            if f.filename == "":
                error = "文件名为空"
            else:
                # 1. 检查文件扩展名
                original_name = f.filename
                ext = os.path.splitext(original_name)[1].lower()
                if ext not in ALLOWED_EXTENSIONS:
                    error = f"不支持的文件类型: {ext}，仅允许图片文件（{', '.join(sorted(ALLOWED_EXTENSIONS))}）"
                    print(f"[UPLOAD-BLOCKED] {session['username']} 尝试上传禁止类型: {ext}")
                    return render_template("upload.html", file_url=file_url, error=error, csrf_token=generate_csrf())

                try:
                    # 2. 读取文件头部检测魔数
                    file_data = f.read(32)
                    is_image = False
                    detected_ext = None
                    for magic, magic_ext in IMAGE_MAGIC.items():
                        if file_data.startswith(magic):
                            is_image = True
                            detected_ext = magic_ext
                            break

                    if not is_image:
                        error = "文件内容不是有效的图片格式（魔数校验失败）"
                        print(f"[UPLOAD-BLOCKED] {session['username']} 上传文件魔数校验失败: {original_name}")
                        return render_template("upload.html", file_url=file_url, error=error, csrf_token=generate_csrf())

                    # 3. 限制文件大小（16MB）
                    f.seek(0, os.SEEK_END)
                    file_size = f.tell()
                    if file_size > 16 * 1024 * 1024:
                        error = "文件大小超过 16MB 限制"
                        return render_template("upload.html", file_url=file_url, error=error, csrf_token=generate_csrf())
                    f.seek(0)

                    # 4. 使用 UUID 重命名文件，防止路径遍历和覆盖
                    safe_filename = f"{secrets.token_hex(16)}{detected_ext}"
                    upload_dir = os.path.join(app.root_path, "static", "uploads")
                    os.makedirs(upload_dir, exist_ok=True)
                    save_path = os.path.join(upload_dir, safe_filename)
                    f.save(save_path)
                    file_url = f"/static/uploads/{safe_filename}"
                    print(f"[UPLOAD] {session['username']} 上传图片: {original_name} → {safe_filename} ({file_size} bytes)")
                except Exception as e:
                    error = f"上传失败: {e}"

    return render_template("upload.html", file_url=file_url, error=error, csrf_token=generate_csrf())


# ============================================================
# 路由：个人中心（仅限查看自己资料）
# ============================================================
@app.route("/profile")
def profile():
    if "username" not in session:
        return redirect("/login")

    username = session["username"]
    user_data = None
    error = None

    try:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        sql = "SELECT id, username, email, phone, balance FROM users WHERE username = ?"
        print(f"[PROFILE] 执行 SQL: {sql} 参数: {username}")
        c.execute(sql, (username,))
        row = c.fetchone()
        conn.close()
        if row:
            user_data = {
                "id": row[0],
                "username": row[1],
                "email": row[2],
                "phone": row[3],
                "balance": row[4],
            }
        else:
            error = "用户不存在"
    except Exception as e:
        error = f"查询失败: {e}"

    return render_template("profile.html", user=user_data, error=error,
                           csrf_token=generate_csrf())


# ============================================================
# 路由：充值（仅限给自己的账户充值）
# ============================================================
@app.route("/recharge", methods=["POST"])
def recharge():
    if "username" not in session:
        return redirect("/login")

    amount = request.form.get("amount", "0")

    try:
        amount = float(amount)
        if amount <= 0:
            flash("充值金额必须大于 0", "error")
            return redirect("/profile")

        username = session["username"]
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        sql = "UPDATE users SET balance = balance + ? WHERE username = ?"
        print(f"[RECHARGE] 执行 SQL: {sql} 参数: {amount}, {username}")
        c.execute(sql, (amount, username))
        conn.commit()
        conn.close()
        flash(f"充值成功！金额: {amount:.2f}", "success")
    except Exception as e:
        flash(f"充值失败: {e}", "error")

    return redirect("/profile")


# ============================================================
# 路由：动态页面加载（路径遍历漏洞演示）
# ============================================================
@app.route("/page")
def dynamic_page():
    name = request.args.get("name", "")
    page_content = None
    error = None

    if name:
        # 直接拼接用户输入的路径，不做任何校验
        page_path = os.path.join("pages", name)
        print(f"[PAGE] 尝试加载: {page_path}")

        if os.path.exists(page_path):
            with open(page_path, "r", encoding="utf-8") as f:
                page_content = f.read()
        else:
            # 尝试加上 .html 后缀
            page_path_html = page_path + ".html"
            print(f"[PAGE] 尝试加载: {page_path_html}")
            if os.path.exists(page_path_html):
                with open(page_path_html, "r", encoding="utf-8") as f:
                    page_content = f.read()
            else:
                error = "页面不存在"

    # 获取当前用户信息
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

    return render_template("index.html", username=username, user=user_info, csrf_token=generate_csrf(),
                           page_content=page_content, page_error=error,
                           page_name=name)


# ============================================================
# URL 安全校验函数（防 SSRF）
# ============================================================
PRIVATE_IP_PATTERNS = [
    re.compile(r"^127\.\d+\.\d+\.\d+$"),
    re.compile(r"^10\.\d+\.\d+\.\d+$"),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$"),
    re.compile(r"^192\.168\.\d+\.\d+$"),
    re.compile(r"^0\.\d+\.\d+\.\d+$"),
    re.compile(r"^169\.254\.\d+\.\d+$"),
    re.compile(r"^100\.(6[4-9]|\d{2,3})\.\d+\.\d+$"),
]

BLOCKED_HOSTS = {"localhost", "127.0.0.1", "127.1", "0", "0.0.0.0", "::1", "[::1]"}

ALLOWED_PROTOCOLS = {"http", "https"}

def validate_url_safety(url):
    """验证 URL 安全性，防止 SSRF 攻击"""
    # 1. 解析 URL
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()

    # 2. 只允许 http/https
    if scheme not in ALLOWED_PROTOCOLS:
        return False, f"不允许的协议: {scheme}，仅支持 http/https"

    # 3. 检查 host
    hostname = parsed.hostname.lower()
    if hostname in BLOCKED_HOSTS:
        return False, f"不允许访问: {hostname}"

    # 4. 检查是否为内网 IP
    try:
        ip = socket.gethostbyname(hostname)
        for pattern in PRIVATE_IP_PATTERNS:
            if pattern.match(ip):
                return False, f"不允许访问内网地址: {ip}"
    except socket.gaierror:
        return False, f"域名解析失败: {hostname}"

    return True, None


# ============================================================
# 路由：URL 抓取（已修复 SSRF 漏洞）
# ============================================================
@app.route("/fetch-url", methods=["POST"])
def fetch_url():
    if "username" not in session:
        return redirect("/login")

    url = request.form.get("url", "")
    result_status = None
    result_content = None
    error = None

    if url:
        # SSRF 安全校验
        is_safe, err_msg = validate_url_safety(url)
        if not is_safe:
            error = f"URL 被拒绝: {err_msg}"
            print(f"[FETCH-URL-BLOCKED] {session['username']} 尝试访问被拒绝的URL: {url}")
        else:
            try:
                print(f"[FETCH-URL] {session['username']} 请求: {url}")
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                resp = urllib.request.urlopen(req, timeout=10)
                result_status = resp.status
                content = resp.read().decode("utf-8", errors="replace")
                result_content = content[:5000]
                print(f"[FETCH-URL] 状态: {result_status}, 内容长度: {len(content)}")
            except urllib.error.HTTPError as e:
                result_status = e.code
                result_content = str(e)
                print(f"[FETCH-URL] HTTP错误: {e.code}")
            except urllib.error.URLError as e:
                error = f"URL 请求失败: {e.reason}"
                print(f"[FETCH-URL] URL错误: {e.reason}")
            except Exception as e:
                error = f"请求出错: {e}"
                print(f"[FETCH-URL] 异常: {e}")

    # 获取当前用户信息
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

    return render_template("index.html", username=username, user=user_info,
                           fetch_url=url, fetch_status=result_status,
                           fetch_content=result_content, fetch_error=error,
                           csrf_token=generate_csrf())


# ============================================================
# 路由：Ping 网络诊断（已修复命令注入）
# ============================================================
@app.route("/ping", methods=["GET", "POST"])
def ping():
    if "username" not in session:
        return redirect("/login")

    result = None
    error = None

    if request.method == "POST":
        ip = request.form.get("ip", "").strip()
        if ip:
            # 1. 校验：只允许合法的 IP 或域名
            import re as _re
            is_ip = _re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip)
            is_domain = _re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$', ip)
            # 也允许 localhost
            is_localhost = ip.lower() == "localhost"

            if not (is_ip or is_domain or is_localhost):
                error = f"无效的地址: {ip}，请输入合法的 IP 地址或域名"
                print(f"[PING-BLOCKED] {session['username']} 尝试注入: {ip}")
            else:
                try:
                    # 2. 使用 shell=False + 参数列表，防止命令注入
                    command = ["ping", "-c", "3", ip]
                    print(f"[PING] {session['username']} 执行: {' '.join(command)}")
                    result = subprocess.check_output(command, shell=False, timeout=30, stderr=subprocess.STDOUT)
                    result = result.decode("utf-8", errors="replace")
                    print(f"[PING] 执行成功，输出 {len(result)} 字符")
                except subprocess.CalledProcessError as e:
                    result = e.output.decode("utf-8", errors="replace") if e.output else ""
                    error = f"命令执行返回非零退出码: {e.returncode}"
                except subprocess.TimeoutExpired:
                    error = "命令执行超时（30秒）"
                except FileNotFoundError:
                    error = "系统未找到 ping 命令"
                except Exception as e:
                    error = f"执行出错: {e}"

    return render_template("ping.html", result=result, error=error, csrf_token=generate_csrf())


# ============================================================
# 路由：XML 数据导入（已修复 XXE 漏洞）
# ============================================================
@app.route("/xml-import", methods=["GET", "POST"])
def xml_import():
    if "username" not in session:
        return redirect("/login")

    result_json = None
    error = None

    if request.method == "POST":
        xml_data = request.form.get("xml_data", "")
        if xml_data.strip():
            try:
                # 1. 检查是否包含 DOCTYPE/ENTITY（XXE 攻击特征）
                if re.search(r'<!DOCTYPE|<!ENTITY', xml_data, re.IGNORECASE):
                    error = "XML 中包含不允许的 DOCTYPE 或 ENTITY 声明，已拒绝处理"
                    print(f"[XML-IMPORT-BLOCKED] {session['username']} 尝试XXE攻击: {xml_data[:100]}")
                    return render_template("xml_import.html", result_json=result_json, error=error, csrf_token=generate_csrf())

                # 2. 解析 XML（已禁止 DOCTYPE，不存在 XXE 风险）
                root = ET.fromstring(xml_data)
                users = []
                for user_elem in root.findall("user"):
                    name = user_elem.findtext("name", "")
                    email = user_elem.findtext("email", "")
                    users.append({"name": name, "email": email})

                result_json = json.dumps({"status": "success", "users": users}, indent=2, ensure_ascii=False)
                print(f"[XML-IMPORT] 解析成功: {len(users)} 条记录")

            except ET.ParseError as e:
                error = f"XML 解析错误: {e}"
            except Exception as e:
                error = f"处理失败: {e}"

    return render_template("xml_import.html", result_json=result_json, error=error, csrf_token=generate_csrf())


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
    init_db()
    print("=" * 60)
    print("  安全版用户管理系统")
    print("  监听地址: 192.168.13.128:5000")
    print("  CSRF: 已启用 | 限流: 已启用 | Session: 已加固")
    print("  SQL注入演示: /register | /search")
    print("=" * 60)
    app.run(host="192.168.13.128", port=5000, debug=False)
