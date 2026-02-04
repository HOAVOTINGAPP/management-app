import os
import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, request, redirect, url_for, render_template_string, flash, session
import csv
from io import StringIO, BytesIO

DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL not set")
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

app = Flask(__name__)
app.secret_key = "change_this_secret"

# ===============================
# SCHEMA
# ===============================

def ensure_schema():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS hoas (
        id SERIAL PRIMARY KEY,
        name TEXT,
        db_name TEXT,
        enabled INTEGER DEFAULT 1
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS hoa_users (
        id SERIAL PRIMARY KEY,
        hoa_id INTEGER,
        email TEXT,
        password TEXT,
        enabled INTEGER DEFAULT 1
    );
    """)

    conn.commit()
    conn.close()

ensure_schema()

# ===============================
# AUTH
# ===============================

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        email = request.form.get("email")
        password = request.form.get("password")
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
        SELECT * FROM hoa_users
        WHERE email=%s AND password=%s AND enabled=1
        """,(email,password))
        user = cur.fetchone()
        conn.close()
        if not user:
            flash("Invalid credentials")
            return redirect("/login")
        session["admin"] = True
        return redirect("/")
    return render_template_string("""
    <h1>Login</h1>
    <form method="post">
    <input name="email">
    <input name="password" type="password">
    <button>Login</button>
    </form>
    """)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

def require_admin():
    if not session.get("admin"):
        return redirect("/login")

# ===============================
# DASHBOARD
# ===============================

@app.route("/")
def dashboard():
    require_admin()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM hoas ORDER BY id")
    hoas = cur.fetchall()
    conn.close()
    return render_template_string("""
    <h1>HOA Management</h1>
    <a href="/hoa/new">Create HOA</a>
    <ul>
    {% for h in hoas %}
      <li>{{h['name']}} – <a href="/hoa/{{h['id']}}">Manage</a></li>
    {% endfor %}
    </ul>
    """, hoas=hoas)

# ===============================
# CREATE HOA
# ===============================

@app.route("/hoa/new", methods=["GET","POST"])
def new_hoa():
    require_admin()
    if request.method=="POST":
        name = request.form.get("name")
        conn = get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO hoas (name,db_name) VALUES (%s,%s)",
                    (name,name.lower().replace(" ","_")))
        conn.commit()
        conn.close()
        return redirect("/")
    return render_template_string("""
    <h1>Create HOA</h1>
    <form method="post">
    <input name="name">
    <button>Create</button>
    </form>
    """)

# ===============================
# HOA USERS
# ===============================

@app.route("/hoa/<int:hoa_id>", methods=["GET","POST"])
def manage_hoa(hoa_id):
    require_admin()
    conn = get_db()
    cur = conn.cursor()

    if request.method=="POST":
        email = request.form.get("email")
        password = request.form.get("password")
        cur.execute("""
        INSERT INTO hoa_users (hoa_id,email,password)
        VALUES (%s,%s,%s)
        """,(hoa_id,email,password))
        conn.commit()

    cur.execute("SELECT * FROM hoas WHERE id=%s",(hoa_id,))
    hoa = cur.fetchone()

    cur.execute("SELECT * FROM hoa_users WHERE hoa_id=%s",(hoa_id,))
    users = cur.fetchall()
    conn.close()

    return render_template_string("""
    <h1>{{hoa['name']}}</h1>
    <h3>Create User</h3>
    <form method="post">
    <input name="email">
    <input name="password">
    <button>Add</button>
    </form>
    <h3>Users</h3>
    <ul>
    {% for u in users %}
      <li>{{u['email']}}</li>
    {% endfor %}
    </ul>
    """, hoa=hoa, users=users)

# ===============================
# EXPORT
# ===============================

@app.route("/export/hoas")
def export_hoas():
    require_admin()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM hoas")
    rows = cur.fetchall()
    conn.close()

    out = StringIO()
    writer = csv.writer(out)
    writer.writerow(["id","name","db_name","enabled"])
    for r in rows:
        writer.writerow([r["id"],r["name"],r["db_name"],r["enabled"]])

    bio = BytesIO(out.getvalue().encode())
    bio.seek(0)
    return send_file(bio, as_attachment=True, download_name="hoas.csv")

@app.route("/export/users")
def export_users():
    require_admin()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM hoa_users")
    rows = cur.fetchall()
    conn.close()

    out = StringIO()
    writer = csv.writer(out)
    writer.writerow(["id","hoa_id","email","enabled"])
    for r in rows:
        writer.writerow([r["id"],r["hoa_id"],r["email"],r["enabled"]])

    bio = BytesIO(out.getvalue().encode())
    bio.seek(0)
    return send_file(bio, as_attachment=True, download_name="users.csv")

# ===============================
# TOGGLE
# ===============================

@app.route("/hoa/<int:hoa_id>/toggle")
def toggle_hoa(hoa_id):
    require_admin()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE hoas SET enabled=1-enabled WHERE id=%s",(hoa_id,))
    conn.commit()
    conn.close()
    return redirect("/")

@app.route("/user/<int:user_id>/toggle")
def toggle_user(user_id):
    require_admin()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE hoa_users SET enabled=1-enabled WHERE id=%s",(user_id,))
    conn.commit()
    conn.close()
    return redirect("/")

# ===============================
# START
# ===============================

if __name__ == "__main__":
    port = int(os.environ.get("PORT",5001))
    app.run(host="0.0.0.0", port=port, debug=False)
