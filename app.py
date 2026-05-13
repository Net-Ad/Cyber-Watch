<<<<<<< HEAD
from flask import Flask, render_template, request, redirect, session, Response, make_response
from database import get_connection
from datetime import datetime, timedelta
import uuid
import cv2

import blocker
import detector

app = Flask(__name__)
app.secret_key = "Group7_netad"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)


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

        cursor.execute(
            "SELECT username, password FROM users WHERE username=%s",
            (username,)
        )

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

        return "Invalid login"

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


import threading

latest_frame = None
frame_lock = threading.Lock()


@app.route("/upload_frame", methods=["POST"])
def upload_frame():
    global latest_frame
    data = request.data
    with frame_lock:
        latest_frame = data
    return "OK", 200


def generate_frames():
    global latest_frame
    while True:
        with frame_lock:
            frame = latest_frame
        if frame is None:
            continue
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')


@app.route("/video_feed")
def video_feed():
    if "user" not in session:
        return "Unauthorized", 403
    return Response(generate_frames(),
                    mimetype='multipart/x-mixed-replace; boundary=frame')
=======
from flask import Flask, render_template, request, redirect, session, Response, make_response
from database import get_connection
from datetime import datetime, timedelta
import uuid
import cv2

import blocker
import detector

app = Flask(__name__)
app.secret_key = "Group7_netad"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)


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

        cursor.execute(
            "SELECT username, password FROM users WHERE username=%s",
            (username,)
        )

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


camera = cv2.VideoCapture(0)
camera.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
camera.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)


def generate_frames():
    while True:
        success, frame = camera.read()
        if not success:
            continue

        _, buffer = cv2.imencode('.jpg', frame)
        frame_bytes = buffer.tobytes()

        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' +
               frame_bytes +
               b'\r\n')


@app.route("/video_feed")
def video_feed():
    if "user" not in session:
        return "Unauthorized", 403

    return Response(generate_frames(),
                    mimetype='multipart/x-mixed-replace; boundary=frame')


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


import atexit

@atexit.register
def release_camera():
    camera.release()


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
>>>>>>> 5ac76773255beb7199aedf6c80e40b0dd7579e78
