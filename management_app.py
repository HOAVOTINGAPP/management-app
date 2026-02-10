import os
import re
import hmac
import hashlib
from datetime import date
import psycopg2
from psycopg2 import sql
from psycopg2.extras import RealDictCursor
from flask import Flask, request, redirect, render_template_string, session

# ======================================================
# Configuration (Render + Supabase)
# ======================================================

DATABASE_URL = os.environ["DATABASE_URL"]
SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-in-production")

# ======================================================
# App setup
# ======================================================

app = Flask(__name__)
app.secret_key = SECRET_KEY
@app.before_request
def auto_disable_expired_hoas():
    enforce_subscription_expiry()

# ======================================================
# DB helpers (NO GLOBAL CONNECTIONS)
# ======================================================

def get_conn():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
def enforce_subscription_expiry():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        UPDATE public.hoas
        SET enabled = FALSE
        WHERE subscription_end < CURRENT_DATE
        AND enabled = TRUE
        AND deleted_at IS NULL
    """)

    conn.commit()
    conn.close()

# ======================================================
# Password security (legacy compatible)
# ======================================================

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def verify_password(stored: str, provided: str) -> bool:
    # Legacy support: plaintext passwords allowed
    if len(stored) != 64:
        return hmac.compare_digest(stored, provided)
    return hmac.compare_digest(stored, hash_password(provided))

# ======================================================
# Initial schema bootstrap (public schema only)
# ======================================================

def init_management_schema():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS public.super_admins (
        id BIGSERIAL PRIMARY KEY,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        enabled BOOLEAN NOT NULL DEFAULT TRUE
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS public.hoas (
        id BIGSERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        schema_name TEXT NOT NULL UNIQUE,
        subscription_start DATE NOT NULL,
        subscription_end DATE NOT NULL,
        enabled BOOLEAN NOT NULL DEFAULT TRUE,
        portal_title TEXT,
        brand_color TEXT DEFAULT '#2563eb',
        logo_url TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        deleted_at TIMESTAMPTZ
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS public.hoa_users (
        id BIGSERIAL PRIMARY KEY,
        hoa_id BIGINT NOT NULL REFERENCES public.hoas(id),
        email TEXT NOT NULL,
        password TEXT NOT NULL,
        enabled BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    """)

    cur.execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS idx_hoa_users_email_hoa
    ON public.hoa_users(hoa_id, email);
    """)

    # Seed default admin if missing
    cur.execute("SELECT 1 FROM public.super_admins WHERE enabled=TRUE;")
    if not cur.fetchone():
        cur.execute(
            "INSERT INTO public.super_admins(username, password, enabled) VALUES (%s,%s,TRUE)",
            ("admin", hash_password("admin123"))
        )

    conn.commit()
    conn.close()

# Run bootstrap once on startup
init_management_schema()

# ======================================================
# Helpers
# ======================================================

def logged_in():
    return "admin" in session

def slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")

def provision_hoa_schema(schema_name: str):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(f"CREATE SCHEMA IF NOT EXISTS {schema_name};")

    cur.execute(f"""
    CREATE TABLE IF NOT EXISTS {schema_name}.owners (
        id BIGSERIAL PRIMARY KEY,
        erf TEXT NOT NULL UNIQUE,
        name TEXT,
        id_number TEXT
    );
    """)

    cur.execute(f"""
    CREATE TABLE IF NOT EXISTS {schema_name}.registrations (
        id BIGSERIAL PRIMARY KEY,
        erf TEXT NOT NULL UNIQUE,
        proxies INTEGER NOT NULL DEFAULT 0,
        otp TEXT
    );
    """)

    cur.execute(f"""
    CREATE TABLE IF NOT EXISTS {schema_name}.topics (
        id BIGSERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        is_open BOOLEAN NOT NULL DEFAULT FALSE
    );
    """)

    cur.execute(f"""
    CREATE TABLE IF NOT EXISTS {schema_name}.options (
        id BIGSERIAL PRIMARY KEY,
        topic_id BIGINT NOT NULL,
        label TEXT NOT NULL
    );
    """)

    cur.execute(f"""
    CREATE TABLE IF NOT EXISTS {schema_name}.votes (
        id BIGSERIAL PRIMARY KEY,
        topic_id BIGINT NOT NULL,
        erf TEXT NOT NULL,
        option_id BIGINT NOT NULL,
        weight INTEGER NOT NULL,
        prev_hash TEXT,
        vote_hash TEXT,
        timestamp TIMESTAMPTZ
    );
    """)

    cur.execute(f"""
    CREATE UNIQUE INDEX IF NOT EXISTS uniq_vote
    ON {schema_name}.votes(topic_id, erf);
    """)

    cur.execute(f"""
    CREATE TABLE IF NOT EXISTS {schema_name}.developer_settings (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        is_active BOOLEAN NOT NULL DEFAULT FALSE,
        base_votes INTEGER NOT NULL DEFAULT 0,
        proxy_count INTEGER NOT NULL DEFAULT 0,
        comment TEXT
    );
    """)

    cur.execute(f"""
    CREATE TABLE IF NOT EXISTS {schema_name}.developer_proxies (
        id BIGSERIAL PRIMARY KEY,
        erf TEXT NOT NULL UNIQUE,
        note TEXT
    );
    """)

    cur.execute(f"""
    CREATE TABLE IF NOT EXISTS {schema_name}.owner_proxies (
        id BIGSERIAL PRIMARY KEY,
        primary_erf TEXT NOT NULL,
        proxy_erf TEXT NOT NULL UNIQUE
    );
    """)

    cur.execute(f"""
    INSERT INTO {schema_name}.developer_settings (id)
    VALUES (1) ON CONFLICT (id) DO NOTHING;
    """)

    conn.commit()
    conn.close()

# ======================================================
# Layout
# ======================================================

BASE_HEAD = """<!doctype html>
<html>
<head>
<title>HOA Management</title>
<meta charset="utf-8">
<style>
:root {
 --bg:#0f172a; --bgp:#f3f4f6; --card:#fff;
 --acc:#2563eb; --accd:#1d4ed8;
 --danger:#b91c1c; --ok:#166534; --border:#e5e7eb;
}
body{margin:0;font-family:system-ui;background:var(--bgp)}
.shell{max-width:1100px;margin:auto;padding:24px}
nav{background:var(--bg);padding:12px;border-radius:12px}
nav a{color:#e5e7eb;margin-right:16px;text-decoration:none}
nav a:hover{text-decoration:underline}
.card{background:var(--card);border-radius:14px;padding:20px;margin-top:16px;
box-shadow:0 14px 35px rgba(0,0,0,.12)}
table{width:100%;border-collapse:collapse;margin-top:10px}
th,td{border:1px solid var(--border);padding:8px;font-size:14px}
th{background:#e5e7eb}
button,a.btn{
 background:var(--acc);color:#fff;padding:6px 12px;
 border-radius:8px;text-decoration:none;border:none;cursor:pointer
}
button:hover,a.btn:hover{background:var(--accd)}
.bad{color:var(--danger);font-weight:600}
.ok{color:var(--ok);font-weight:600}
.small{font-size:13px}
</style>
</head>
<body>
<div class="shell">
<nav>
 <a href="/dashboard/hoa-create">HOA Create</a>
 <a href="/dashboard/hoa-user-create">HOA User Create</a>
 <a href="/dashboard/manage-hoa">Manage HOA</a>
 <a href="/dashboard/security">Security</a>
 <a href="/logout">Logout</a>
 <a href="/dashboard/recycle-bin">Recycle Bin</a>
</nav>
"""

BASE_TAIL = "</div></body></html>"

# ======================================================
# Routes — Login / Logout
# ======================================================

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form["u"]
        p = request.form["p"]

        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM public.super_admins WHERE username=%s AND enabled=TRUE",
            (u,)
        )
        admin = cur.fetchone()
        conn.close()

        if not admin or not verify_password(admin["password"], p):
            return render_template_string("<h3>Invalid login</h3>")

        session["admin"] = u
        return redirect("/dashboard/hoa-create")

    return render_template_string("""
    <div class=card><h2>Management Login</h2>
    <form method=post>
        <input name=u placeholder=Username><br><br>
        <input type=password name=p placeholder=Password><br><br>
        <button>Login</button>
    </form></div>
    """)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ======================================================
# HOA Create
# ======================================================

@app.route("/dashboard/hoa-create", methods=["GET", "POST"])
def hoa_create():
    if not logged_in():
        return redirect("/")

    msg = None
    if request.method == "POST":
        name = request.form["name"]
        start = request.form["start"]
        end = request.form["end"]

        schema_name = f"hoa_{slugify(name)}"

        conn = get_conn()
        cur = conn.cursor()

        portal_title = request.form.get("portal_title") or name
        brand_color = request.form.get("brand_color") or "#2563eb"
        logo_url = request.form.get("logo_url")

        cur.execute("""
        INSERT INTO public.hoas (
            name,
            schema_name,
            subscription_start,
            subscription_end,
            portal_title,
            brand_color,
            logo_url
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s)
        RETURNING id;
        """, (
            name,
            schema_name,
            start,
            end,
            portal_title,
            brand_color,
            logo_url
        ))


        hoa_id = cur.fetchone()["id"]
        conn.commit()
        conn.close()

        provision_hoa_schema(schema_name)

        msg = "HOA created"

    return render_template_string(
        BASE_HEAD + """
<div class=card>
<h2>Create HOA</h2>
{% if msg %}<p class=ok>{{msg}}</p>{% endif %}
<form method=post>
<p>Name<br><input name=name required></p>

<p>Portal Title<br>
<input name=portal_title placeholder="Optional custom title"></p>

<p>Brand Color<br>
<input name=brand_color placeholder="#2563eb"></p>

<p>Logo URL<br>
<input name=logo_url placeholder="https://example.com/logo.png"></p>

<p>Start<br><input type=date name=start required></p>
<p>End<br><input type=date name=end required></p>

<button>Create</button>
</form>

""" + BASE_TAIL,
        msg=msg
    )

# ======================================================
# HOA User Create
# ======================================================

@app.route("/dashboard/hoa-user-create", methods=["GET", "POST"])
def hoa_user_create():
    if not logged_in():
        return redirect("/")

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    SELECT id,name
    FROM public.hoas
    WHERE deleted_at IS NULL
    ORDER BY name;
    """)
    hoas = cur.fetchall()

    msg = None
    if request.method == "POST":
        cur.execute("""
        INSERT INTO public.hoa_users (hoa_id,email,password)
        VALUES (%s,%s,%s)
        """, (
            request.form["hoa"],
            request.form["email"],
            request.form["password"]
        ))
        conn.commit()
        msg = "User created"

    conn.close()

    return render_template_string(
        BASE_HEAD + """
<div class=card>
<h2>Create HOA User</h2>
{% if msg %}<p class=ok>{{msg}}</p>{% endif %}
<form method=post>
<select name=hoa>
{% for h in hoas %}<option value="{{h.id}}">{{h.name}}</option>{% endfor %}
</select><br><br>
<input name=email placeholder=Email required><br><br>
<input name=password placeholder=Password required><br><br>
<button>Create User</button>
</form></div>
""" + BASE_TAIL,
        hoas=hoas,
        msg=msg
    )

# ======================================================
# Manage HOAs
# ======================================================

@app.route("/dashboard/manage-hoa")
def manage_hoa():
    if not logged_in():
        return redirect("/")

    today = date.today()

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    SELECT *
    FROM public.hoas
    WHERE deleted_at IS NULL
    ORDER BY name;
    """)
    hoas = cur.fetchall()
    conn.close()

    for h in hoas:
        if h["subscription_start"] and isinstance(h["subscription_start"], str):
            h["subscription_start"] = date.fromisoformat(h["subscription_start"])
        if h["subscription_end"] and isinstance(h["subscription_end"], str):
            h["subscription_end"] = date.fromisoformat(h["subscription_end"])

    return render_template_string(
        BASE_HEAD + """
<div class=card>
<h2>Manage HOAs</h2>
<table>
<tr><th>Name</th><th>Subscription</th><th>Status</th><th>Actions</th></tr>
{% for h in hoas %}
{% set expired = h.subscription_end < today %}
<tr>
<td>{{h.name}}</td>
<td>{{h.subscription_start}} → {{h.subscription_end}}</td>
<td class="{{'bad' if expired or not h.enabled else 'ok'}}">
{{'Expired' if expired else 'Disabled' if not h.enabled else 'Active'}}
</td>
<td>

<a class="btn small" href="/dashboard/manage-hoa/{{h.id}}/users">Users</a>

<a class="btn small" href="/toggle-hoa/{{h.id}}">Toggle</a>

<a class="btn small" href="/dashboard/manage-hoa/{{h.id}}/edit">Edit</a>

<a class="btn small bad"
   onclick="return confirm('Disable HOA? This will prevent login and voting.')"
   href="/delete-hoa/{{h.id}}">
Hard Delete
</a>

</td>
</tr>
{% endfor %}
</table>
</div>
""" + BASE_TAIL,
        hoas=hoas,
        today=today
    )

# ======================================================
# Recycle Bin — View deleted HOAs
# ======================================================

@app.route("/dashboard/recycle-bin")
def recycle_bin():

    if not logged_in():
        return redirect("/")

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT *
        FROM public.hoas
        WHERE deleted_at IS NOT NULL
        ORDER BY deleted_at DESC
    """)

    hoas = cur.fetchall()

    conn.close()

    return render_template_string(
        BASE_HEAD + """
<div class=card>

<h2>Recycle Bin</h2>

<table>

<tr>
<th>Name</th>
<th>Schema</th>
<th>Deleted At</th>
<th>Actions</th>
</tr>

{% for h in hoas %}

<tr>

<td>{{h.name}}</td>

<td>{{h.schema_name}}</td>

<td>{{h.deleted_at}}</td>

<td>

<a class="btn small"
href="/restore-hoa/{{h.id}}">
Restore
</a>

<a class="btn small bad"
href="/permanent-delete-hoa/{{h.id}}">
Permanent Delete
</a>

</td>

</tr>

{% endfor %}

</table>

</div>
""" + BASE_TAIL,
        hoas=hoas
    )

# ======================================================
# Restore HOA from recycle bin
# ======================================================

@app.route("/restore-hoa/<int:id>")
def restore_hoa(id):

    if not logged_in():
        return redirect("/")

    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        """
        UPDATE public.hoas
        SET deleted_at = NULL,
            enabled = TRUE
        WHERE id=%s
        """,
        (id,)
    )

    conn.commit()
    conn.close()

    return redirect("/dashboard/recycle-bin")

# ======================================================
# Permanent Delete HOA (irreversible)
# ======================================================

@app.route("/permanent-delete-hoa/<int:id>", methods=["GET", "POST"])
def permanent_delete_hoa(id):

    if not logged_in():
        return redirect("/")

    conn = get_conn()
    cur = conn.cursor()

    if request.method == "GET":

        return render_template_string(
            BASE_HEAD + """
<div class=card>

<h2>Permanent Delete HOA</h2>

<p class=bad>
This permanently deletes ALL HOA data.
</p>

<form method=post>

Superadmin Password:<br>
<input type=password name=password required>

<br><br>

<button class="btn bad">
Confirm Permanent Delete
</button>

</form>

</div>
""" + BASE_TAIL
        )

    password = request.form["password"]

    cur.execute(
        "SELECT password FROM public.super_admins LIMIT 1"
    )

    admin = cur.fetchone()

    if not admin or not verify_password(admin["password"], password):

        conn.close()

        return render_template_string(
            BASE_HEAD + """
<div class=card>
Invalid password
</div>
""" + BASE_TAIL
        )

    cur.execute(
        "SELECT schema_name FROM public.hoas WHERE id=%s",
        (id,)
    )

    hoa = cur.fetchone()

    if hoa:

        schema = hoa["schema_name"]

        from psycopg2 import sql

        cur.execute(
            sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE")
            .format(sql.Identifier(schema))
        )

        cur.execute(
            "DELETE FROM public.hoa_users WHERE hoa_id=%s",
            (id,)
        )

        cur.execute(
            "DELETE FROM public.hoas WHERE id=%s",
            (id,)
        )

    conn.commit()
    conn.close()

    return redirect("/dashboard/recycle-bin")

# ======================================================
# Manage HOA Users
# ======================================================

@app.route("/dashboard/manage-hoa/<int:hoa_id>/users")
def manage_hoa_users(hoa_id):
    if not logged_in():
        return redirect("/")

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT name FROM public.hoas WHERE id=%s", (hoa_id,))
    hoa = cur.fetchone()

    cur.execute(
        "SELECT id,email,enabled FROM public.hoa_users WHERE hoa_id=%s",
        (hoa_id,)
    )
    users = cur.fetchall()
    conn.close()

    return render_template_string(
        BASE_HEAD + """
<div class=card>
<h2>Users for HOA: {{hoa.name}}</h2>
<a href="/dashboard/manage-hoa" class="btn small">← Back</a>
<table>
<tr><th>Email</th><th>Status</th><th>Actions</th></tr>
{% for u in users %}
<tr>
<td>{{u.email}}</td>
<td class="{{'ok' if u.enabled else 'bad'}}">{{'Enabled' if u.enabled else 'Disabled'}}</td>
<td>
<a class="btn small" href="/toggle-user/{{u.id}}">Toggle</a>
</td>
</tr>
{% endfor %}
</table>
</div>
""" + BASE_TAIL,
        hoa=hoa,
        users=users
    )

# ======================================================
# Security
# ======================================================

@app.route("/dashboard/security", methods=["GET", "POST"])
def dashboard_security():
    if not logged_in():
        return redirect("/")

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, username FROM public.super_admins WHERE enabled=TRUE LIMIT 1"
    )
    admin = cur.fetchone()

    msg = None
    if request.method == "POST":
        new_user = request.form["username"].strip()
        new_pass = request.form["password"].strip()

        if len(new_user) < 3:
            msg = "Username too short"
        elif len(new_pass) < 6:
            msg = "Password must be at least 6 characters"
        else:
            cur.execute("UPDATE public.super_admins SET enabled=FALSE")
            cur.execute(
                "UPDATE public.super_admins SET username=%s, password=%s, enabled=TRUE WHERE id=%s",
                (new_user, hash_password(new_pass), admin["id"])
            )
            conn.commit()
            session["admin"] = new_user
            msg = "Credentials updated"

    conn.close()

    return render_template_string(
        BASE_HEAD + """
<div class=card>
<h2>Security</h2>
{% if msg %}<p class=ok>{{msg}}</p>{% endif %}
<form method=post>
<p>Username<br>
<input name=username value="{{admin.username}}" required></p>
<p>New Password<br>
<input type=password name=password required></p>
<button>Update Credentials</button>
</form>
<p class=small>Password is stored securely using SHA-256 hashing.</p>
</div>
""" + BASE_TAIL,
        admin=admin,
        msg=msg
    )

# ======================================================
# Toggle actions
# ======================================================

@app.route("/toggle-hoa/<int:id>")
def toggle_hoa(id):
    if not logged_in():
        return redirect("/")
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE public.hoas SET enabled = NOT enabled WHERE id=%s", (id,))
    conn.commit()
    conn.close()
    return redirect("/dashboard/manage-hoa")

@app.route("/toggle-user/<int:id>")
def toggle_user(id):
    if not logged_in():
        return redirect("/")
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE public.hoa_users SET enabled = NOT enabled WHERE id=%s", (id,))
    conn.commit()
    conn.close()
    return redirect(request.referrer or "/dashboard/manage-hoa")

# ======================================================
# Edit HOA subscription (renewal support)
# ======================================================

@app.route("/dashboard/manage-hoa/<int:id>/edit", methods=["GET", "POST"])
def edit_hoa(id):

    if not logged_in():
        return redirect("/")

    conn = get_conn()
    cur = conn.cursor()

    if request.method == "POST":

        start = request.form["start"]
        end = request.form["end"]

        cur.execute(
            """
            UPDATE public.hoas
            SET subscription_start=%s,
                subscription_end=%s,
                enabled=TRUE
            WHERE id=%s
            """,
            (start, end, id)
        )

        conn.commit()
        conn.close()

        return redirect("/dashboard/manage-hoa")

    cur.execute(
        """
        SELECT *
        FROM public.hoas
        WHERE id=%s
        """,
        (id,)
    )

    hoa = cur.fetchone()

    conn.close()

    return render_template_string(
        BASE_HEAD + """
<div class=card>

<h2>Edit HOA Subscription</h2>

<form method=post>

<p>
Subscription Start<br>
<input type=date name=start
value="{{hoa.subscription_start}}" required>
</p>

<p>
Subscription End<br>
<input type=date name=end
value="{{hoa.subscription_end}}" required>
</p>

<button>Save Changes</button>

</form>

</div>
""" + BASE_TAIL,
        hoa=hoa
    )

# ======================================================
# Delete actions (legacy routes preserved)
# ======================================================

@app.route("/delete-user/<int:id>")
def delete_user(id):
    if not logged_in():
        return redirect("/")

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("DELETE FROM public.hoa_users WHERE id=%s", (id,))

    conn.commit()
    conn.close()

    return redirect(request.referrer or "/dashboard/manage-hoa")


@app.route("/delete-hoa/<int:id>", methods=["GET", "POST"])
def delete_hoa(id):

    if not logged_in():
        return redirect("/")

    conn = get_conn()
    cur = conn.cursor()

    # SHOW PASSWORD CONFIRMATION FORM
    if request.method == "GET":

        return render_template_string(
            BASE_HEAD + """
<div class=card>

<h2>Confirm HARD DELETE</h2>

<p class=bad>
This will permanently delete the HOA and ALL voting data.
This action cannot be undone.
</p>

<form method=post>

<p>
Superadmin Password<br>
<input type=password name=password required>
</p>

<button class="btn bad">Confirm Hard Delete</button>

</form>

</div>
""" + BASE_TAIL
        )

    # VERIFY PASSWORD
    password = request.form["password"]

    cur.execute(
        "SELECT password FROM public.super_admins WHERE enabled=TRUE LIMIT 1"
    )

    admin = cur.fetchone()

    if not admin or not verify_password(admin["password"], password):

        conn.close()

        return render_template_string(
            BASE_HEAD + """
<div class=card>
<p class=bad>Invalid superadmin password.</p>
<a href="/dashboard/manage-hoa" class="btn small">Back</a>
</div>
""" + BASE_TAIL
        )

    # GET SCHEMA NAME
    cur.execute(
        "SELECT schema_name FROM public.hoas WHERE id=%s",
        (id,)
    )

    hoa = cur.fetchone()

    if not hoa:
        conn.close()
        return redirect("/dashboard/manage-hoa")

    schema = hoa["schema_name"]

    # MOVE TO RECYCLE BIN (do not drop schema yet)

    cur.execute(
        """
        UPDATE public.hoas
        SET deleted_at = NOW(),
            enabled = FALSE
        WHERE id=%s
        """,
        (id,)
    )


    conn.commit()
    conn.close()

    return redirect("/dashboard/manage-hoa")

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
