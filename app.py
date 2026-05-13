from flask import Flask, render_template, request, redirect, session, Response, make_response
from flask_sock import Sock
from database import get_connection
from datetime import datetime, timedelta
import uuid
import threading
import json

import blocker
import detector

app = Flask(__name__)
sock = Sock(app)
app.secret_key = "Group7_netad"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

# WebRTC signaling
camera_ws = None
viewers = []
ws_lock = threading.Lock()


def get_device_id():
    device_id = request.cookies.get("device_id")
    if not device_id:
        device_id = str(uuid.uuid4())
    return device_id


def save_log(device_id, event_type, status):
    conn = get_connection()
    cursor = conn.cursor()
    philippines_time = datetime.utcnow() + timedelta(hours=8)
    try:
        cursor.execute("""
            INSERT INTO security_logs (device_id, event_type, status, created_at)
            VALUES (%s, %s, %s, %s)
        """, (device_id, event_type, status, philippines_time))
        conn.commit()
    except:
        conn.rollback()
    finally:
        conn.close()


@app.route("/", methods=["GET", "POST"])
def login():
    device_id = get_device_id()

    if blocker.is_blocked(device_id):
        return "Access Denied: Your device is permanently blocked.", 403

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username, password FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and user[1] == password:
            session.permanent = True
            session["user"] = username
            detector.clear_failed_attempts(device_id)
            save_log(device_id, f"Login Success: {username}", "SUCCESS")
            resp = make_response(redirect("/dashboard"))
            resp.set_cookie("device_id", device_id, max_age=60*60*24*365)
            return resp

        save_log(device_id, f"Login Failed: {username}", "FAILED")
        detector.register_failed_attempt(device_id)

        if detector.detect_attack(device_id):
            blocker.block_device(device_id, "Brute force detected")
            save_log(device_id, "Brute Force Detected", "ALERT")
            save_log(device_id, "DEVICE BLOCKED", "BLOCKED")
            return "Security Alert: Device Blocked.", 403

        return render_template("login.html", error="Invalid username or password.")

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE status='SUCCESS' AND created_at >= CURRENT_DATE")
    today_access = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE status='FAILED' AND created_at >= CURRENT_DATE")
    unauthorized = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM blocked_ips")
    unique_attackers = cursor.fetchone()[0]

    cursor.execute("""
        SELECT device_id, event_type, status, created_at
        FROM security_logs
        ORDER BY created_at DESC
        LIMIT 7
    """)
    recent_alerts = cursor.fetchall()
    conn.close()

    return render_template(
        "dashboard.html",
        user=session["user"],
        today_access=today_access,
        unauthorized=unauthorized,
        unique_attackers=unique_attackers,
        recent_alerts=recent_alerts
    )


@app.route("/live-cctv")
def live_cctv():
    if "user" not in session:
        return redirect("/")
    return render_template("live_cctv.html", user=session["user"])


@app.route("/camera")
def camera_page():
    return render_template("camera.html")


@app.route("/threat-logs")
def threat_logs():
    if "user" not in session:
        return redirect("/")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT device_id, event_type, status, created_at
        FROM security_logs
        ORDER BY created_at DESC
    """)
    logs = cursor.fetchall()
    conn.close()

    return render_template("threat_logs.html", user=session["user"], logs=logs)


@app.route("/analytics")
def analytics():
    if "user" not in session:
        return redirect("/")

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE status='SUCCESS'")
    success_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE status='FAILED'")
    failed_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM blocked_ips")
    blocked_count = cursor.fetchone()[0]

    conn.close()

    return render_template(
        "analytics.html",
        user=session["user"],
        success_count=success_count,
        failed_count=failed_count,
        blocked_count=blocked_count
    )


# --- WebRTC Signaling via WebSockets ---

@sock.route("/ws/camera")
def ws_camera(ws):
    global camera_ws
    with ws_lock:
        camera_ws = ws
    print("Camera connected")
    try:
        while True:
            data = ws.receive()
            if data is None:
                break
            # Forward camera's signaling messages to all viewers
            with ws_lock:
                dead = []
                for viewer in viewers:
                    try:
                        viewer.send(data)
                    except:
                        dead.append(viewer)
                for d in dead:
                    viewers.remove(d)
    finally:
        with ws_lock:
            camera_ws = None
        print("Camera disconnected")


@sock.route("/ws/viewer")
def ws_viewer(ws):
    with ws_lock:
        viewers.append(ws)
    print("Viewer connected")
    try:
        while True:
            data = ws.receive()
            if data is None:
                break
            # Forward viewer's signaling messages to camera
            with ws_lock:
                if camera_ws:
                    try:
                        camera_ws.send(data)
                    except:
                        pass
    finally:
        with ws_lock:
            if ws in viewers:
                viewers.remove(ws)
        print("Viewer disconnected")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)