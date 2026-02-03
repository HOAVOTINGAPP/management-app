import hashlib
import hmac
import os
import re
import sqlite3
from datetime import date
from flask import Flask, request, redirect, render_template_string, session

# ================================
# PASSWORD SECURITY
# ================================

def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def verify_password(stored, provided):
    # Backward compatible: allow old plaintext passwords
    if len(stored) != 64:
        return hmac.compare_digest(stored, provided)
    return hmac.compare_digest(stored, hash_password(provided))

# -------------------------------------------------
# App setup
# -------------------------------------------------

app = Flask(__name__)
app.secret_key = "change_this_in_production"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# management/db/management.db is the real database
DB_DIR = os.path.join(BASE_DIR, "management", "db")
DB_PATH = os.path.join(DB_DIR, "management.db")
HOA_DB_DIR = os.path.join(os.path.dirname(BASE_DIR), "hoa_databases")

os.makedirs(DB_DIR, exist_ok=True)
os.makedirs(HOA_DB_DIR, exist_ok=True)

# -------------------------------------------------
# Layout
# -------------------------------------------------

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
</nav>
"""

BASE_TAIL = "</div></body></html>"

# -------------------------------------------------
# DB helpers
# -------------------------------------------------

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    c = db().cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS super_admins(
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,
        enabled INTEGER DEFAULT 1)
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS hoas(
        id INTEGER PRIMARY KEY,
        name TEXT,
        db_path TEXT,
        subscription_start TEXT,
        subscription_end TEXT,
        enabled INTEGER DEFAULT 1)
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS hoa_users(
        id INTEGER PRIMARY KEY,
        hoa_id INTEGER,
        email TEXT,
        password TEXT,
        enabled INTEGER DEFAULT 1)
    """)

    if not c.execute("SELECT 1 FROM super_admins").fetchone():
        c.execute(
            "INSERT INTO super_admins(username,password) VALUES(?,?)",
            ("admin", hash_password("admin123"))
        )

    c.connection.commit()

def logged():
    return "admin" in session

def slug(name):
    return re.sub(r"[^a-z0-9]+","_",name.lower())

# -------------------------------------------------
# Login
# -------------------------------------------------

@app.route("/", methods=["GET","POST"])
def login():
    if request.method == "POST":
        u = request.form["u"]
        p = request.form["p"]

        cur = db()
        admin = cur.execute(
            "SELECT * FROM super_admins WHERE username=? AND enabled=1",
            (u,)
        ).fetchone()

        if not admin or not verify_password(admin[2], p):   # admin[2] = password column
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

# -------------------------------------------------
# HOA Create
# -------------------------------------------------

@app.route("/dashboard/hoa-create",methods=["GET","POST"])
def hoa_create():
    if not logged(): return redirect("/")
    msg=None
    if request.method=="POST":
        n,s,e=request.form["name"],request.form["start"],request.form["end"]
        path=os.path.join(HOA_DB_DIR,slug(n)+".db")
        db().execute(
            "INSERT INTO hoas(name,db_path,subscription_start,subscription_end) VALUES(?,?,?,?)",
            (n,path,s,e)
        ).connection.commit()
        sqlite3.connect(path).close()
        msg="HOA created"
    return render_template_string(
        BASE_HEAD+"""
<div class=card>
<h2>Create HOA</h2>
{% if msg %}<p class=ok>{{msg}}</p>{% endif %}
<form method=post>
<p>Name<br><input name=name required></p>
<p>Start<br><input type=date name=start required></p>
<p>End<br><input type=date name=end required></p>
<button>Create</button>
</form></div>"""+BASE_TAIL,msg=msg)

# -------------------------------------------------
# HOA User Create (manual)
# -------------------------------------------------

@app.route("/dashboard/hoa-user-create",methods=["GET","POST"])
def hoa_user_create():
    if not logged(): return redirect("/")
    c=db()
    hoas=c.execute("SELECT id,name FROM hoas").fetchall()
    msg=None
    if request.method=="POST":
        c.execute(
            "INSERT INTO hoa_users(hoa_id,email,password) VALUES(?,?,?)",
            (request.form["hoa"],request.form["email"],request.form["password"])
        )
        c.commit()
        msg="User created"
    return render_template_string(
        BASE_HEAD+"""
<div class=card>
<h2>Create HOA User</h2>
{% if msg %}<p class=ok>{{msg}}</p>{% endif %}
<form method=post>
<select name=hoa>
{% for h in hoas %}<option value="{{h[0]}}">{{h[1]}}</option>{% endfor %}
</select><br><br>
<input name=email placeholder=Email required><br><br>
<input name=password placeholder=Password required><br><br>
<button>Create User</button>
</form></div>"""+BASE_TAIL,hoas=hoas,msg=msg)

# -------------------------------------------------
# Manage HOAs
# -------------------------------------------------

@app.route("/dashboard/manage-hoa")
def manage_hoa():
    if not logged(): return redirect("/")
    today=str(date.today())
    hoas=db().execute("SELECT * FROM hoas").fetchall()
    return render_template_string(
        BASE_HEAD+"""
<div class=card>
<h2>Manage HOAs</h2>
<table>
<tr><th>Name</th><th>Subscription</th><th>Status</th><th>Actions</th></tr>
{% for h in hoas %}
{% set expired = h[4] < today %}
<tr>
<td>{{h[1]}}</td>
<td>{{h[3]}} → {{h[4]}}</td>
<td class="{{'bad' if expired or not h[5] else 'ok'}}">
{{'Expired' if expired else 'Disabled' if not h[5] else 'Active'}}
</td>
<td>
<a class="btn small" href="/dashboard/manage-hoa/{{h[0]}}/users">Users</a>
<a class="btn small" href="/toggle-hoa/{{h[0]}}">Toggle</a>
<a class="btn small" href="/delete-hoa/{{h[0]}}" onclick="return confirm('Delete HOA?')">Delete</a>
</td>
</tr>
{% endfor %}
</table>
</div>
"""+BASE_TAIL,hoas=hoas,today=today)

# -------------------------------------------------
# Security – change admin username & password
# -------------------------------------------------

@app.route("/dashboard/security", methods=["GET", "POST"])
def dashboard_security():
    if not logged():
        return redirect("/")

    msg = None
    cur = db()

    admin = cur.execute(
        "SELECT id, username FROM super_admins WHERE enabled=1 LIMIT 1"
    ).fetchone()

    if request.method == "POST":
        new_user = request.form["username"].strip()
        new_pass = request.form["password"].strip()

        if len(new_user) < 3:
            msg = "Username too short"
        elif len(new_pass) < 6:
            msg = "Password must be at least 6 characters"
        else:
            # Disable all admins
            cur.execute("UPDATE super_admins SET enabled=0")

            # Update the primary admin
            cur.execute(
                "UPDATE super_admins SET username=?, password=?, enabled=1 WHERE id=?",
                (new_user, hash_password(new_pass), admin["id"])
            )

            cur.commit()
            session["admin"] = new_user
            msg = "Credentials updated"

    return render_template_string(
        BASE_HEAD + """
<div class=card>
<h2>Security</h2>

{% if msg %}<p class=ok>{{msg}}</p>{% endif %}

<form method=post>
<p>Username<br>
<input name=username value="{{admin['username']}}" required></p>

<p>New Password<br>
<input type=password name=password required></p>

<button>Update Credentials</button>
</form>

<p class=small>
Password is stored securely using SHA-256 hashing.
</p>

</div>
""" + BASE_TAIL,
        admin=admin,
        msg=msg
    )

# -------------------------------------------------
# Manage users PER HOA
# -------------------------------------------------

@app.route("/dashboard/manage-hoa/<int:hoa_id>/users")
def manage_hoa_users(hoa_id):
    if not logged(): return redirect("/")
    c=db()
    hoa=c.execute("SELECT name FROM hoas WHERE id=?", (hoa_id,)).fetchone()
    users=c.execute(
        "SELECT id,email,enabled FROM hoa_users WHERE hoa_id=?",(hoa_id,)
    ).fetchall()
    return render_template_string(
        BASE_HEAD+"""
<div class=card>
<h2>Users for HOA: {{hoa[0]}}</h2>
<a href="/dashboard/manage-hoa" class="btn small">← Back</a>
<table>
<tr><th>Email</th><th>Status</th><th>Actions</th></tr>
{% for u in users %}
<tr>
<td>{{u[1]}}</td>
<td class="{{'ok' if u[2] else 'bad'}}">{{'Enabled' if u[2] else 'Disabled'}}</td>
<td>
<a class="btn small" href="/toggle-user/{{u[0]}}">Toggle</a>
<a class="btn small" href="/delete-user/{{u[0]}}" onclick="return confirm('Delete user?')">Delete</a>
</td>
</tr>
{% endfor %}
</table>
</div>
"""+BASE_TAIL,hoa=hoa,users=users)

# -------------------------------------------------
# Actions
# -------------------------------------------------

@app.route("/toggle-hoa/<int:id>")
def toggle_hoa(id):
    db().execute("UPDATE hoas SET enabled=1-enabled WHERE id=?", (id,)).connection.commit()
    return redirect("/dashboard/manage-hoa")

@app.route("/delete-hoa/<int:id>")
def delete_hoa(id):
    c=db()
    row=c.execute("SELECT db_path FROM hoas WHERE id=?", (id,)).fetchone()
    if row and os.path.exists(row[0]): os.remove(row[0])
    c.execute("DELETE FROM hoa_users WHERE hoa_id=?", (id,))
    c.execute("DELETE FROM hoas WHERE id=?", (id,))
    c.commit()
    return redirect("/dashboard/manage-hoa")

@app.route("/toggle-user/<int:id>")
def toggle_user(id):
    db().execute("UPDATE hoa_users SET enabled=1-enabled WHERE id=?", (id,)).connection.commit()
    return redirect(request.referrer or "/dashboard/manage-hoa")

@app.route("/delete-user/<int:id>")
def delete_user(id):
    db().execute("DELETE FROM hoa_users WHERE id=?", (id,)).connection.commit()
    return redirect(request.referrer or "/dashboard/manage-hoa")

# -------------------------------------------------

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
