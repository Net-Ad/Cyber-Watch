from flask import Flask, render_template, request, redirect, session, Response, make_response, jsonify
from database import get_connection
from datetime import datetime, timedelta
import uuid
import threading
import blocker
import detector
import os
try:
    import requests as http_requests
except ImportError:
    http_requests = None

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)


latest_frame = None
frame_lock = threading.Lock()

# CCTV camera configuration (stored in memory; persists while server runs)
cctv_config = {
    "cameras": []
}
cctv_config_lock = threading.Lock()

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
            INSERT INTO security_logs
            (device_id, event_type, status, created_at)
            VALUES (%s, %s, %s, %s)
        """, (
            device_id,
            event_type,
            status,
            philippines_time
        ))

        conn.commit()

    except:
        conn.rollback()

    finally:
        conn.close()


from werkzeug.security import check_password_hash

@app.route("/", methods=["GET", "POST"])
def login():
    device_id = get_device_id()

    if blocker.is_blocked(device_id):
        block_reason = blocker.get_block_reason(device_id)
        return render_template(
            "login.html",
            blocked=True,
            block_reason=block_reason or "Your device has been permanently blocked."
        ), 403

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT username, password
            FROM users
            WHERE username=%s
        """, (username,))

        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[1], password):
            session.permanent = True
            session["user"] = username

            detector.clear_failed_attempts(device_id)

            save_log(device_id, f"Login Success: {username}", "SUCCESS")

            response = make_response(redirect("/dashboard"))
            response.set_cookie(
                "device_id",
                device_id,
                max_age=60 * 60 * 24 * 365,
                httponly=True,
                samesite="Lax"
            )
            return response

        save_log(device_id, f"Login Failed: {username}", "FAILED")
        detector.register_failed_attempt(device_id)

        if detector.detect_attack(device_id):
            blocker.block_device(device_id, "Too many failed login attempts (brute force detected)")
            save_log(device_id, "Brute Force Detected", "ALERT")
            save_log(device_id, "DEVICE BLOCKED", "BLOCKED")
            return render_template(
                "login.html",
                blocked=True,
                block_reason="Too many failed login attempts — your device has been permanently blocked."
            ), 403

        failed_count = detector.get_failed_count(device_id)
        attempts_left = 5 - failed_count
        warning = None

        if attempts_left <= 2:
            warning = f"⚠ Warning: {attempts_left} attempt{'s' if attempts_left != 1 else ''} left before your device is permanently blocked."

        response = make_response(
            render_template(
                "login.html",
                error="Invalid username or password.",
                warning=warning
            )
        )
        response.set_cookie(
            "device_id",
            device_id,
            max_age=60 * 60 * 24 * 365,
            httponly=True,
            samesite="Lax"
        )
        return response

    response = make_response(render_template("login.html"))
    response.set_cookie(
        "device_id",
        device_id,
        max_age=60 * 60 * 24 * 365,
        httponly=True,
        samesite="Lax"
    )
    return response

    response = make_response(
        render_template("login.html")
    )

    response.set_cookie(
        "device_id",
        device_id,
        max_age=60 * 60 * 24 * 365,
        httponly=True,
        samesite="Lax"
    )

    return response


@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/")

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM security_logs
        WHERE status='SUCCESS'
        AND created_at >= CURRENT_DATE
    """)
    today_access = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM security_logs
        WHERE status='FAILED'
        AND created_at >= CURRENT_DATE
    """)
    unauthorized = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM blocked_devices
    """)
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

    return render_template(
        "live_cctv.html",
        user=session["user"]
    )


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
        LIMIT 50
    """)

    logs = cursor.fetchall()

    conn.close()

    return render_template(
        "threat_logs.html",
        user=session["user"],
        logs=logs
    )


@app.route("/analytics")
def analytics():

    if "user" not in session:
        return redirect("/")

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM security_logs
        WHERE status='SUCCESS'
    """)
    success_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM security_logs
        WHERE status='FAILED'
    """)
    failed_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM blocked_devices
    """)
    blocked_count = cursor.fetchone()[0]

    conn.close()

    return render_template(
        "analytics.html",
        user=session["user"],
        success_count=success_count,
        failed_count=failed_count,
        blocked_count=blocked_count
    )


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


@app.route("/cctv-config", methods=["GET", "POST"])
def cctv_config_route():
    """Save or retrieve IP camera configuration."""
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 403

    global cctv_config

    if request.method == "POST":
        data = request.get_json()
        cameras = data.get("cameras", [])
        # Validate: each camera needs a name and url
        validated = []
        for cam in cameras:
            url = cam.get("url", "").strip()
            name = cam.get("name", "").strip()
            if url and name:
                validated.append({"name": name, "url": url})
        with cctv_config_lock:
            cctv_config["cameras"] = validated
        return jsonify({"status": "ok", "cameras": validated})

    with cctv_config_lock:
        return jsonify(cctv_config)


@app.route("/cctv-proxy")
def cctv_proxy():
    """
    Proxy a single JPEG snapshot from an IP camera URL.
    Supports:
      - MJPEG HTTP streams  (grabs one frame)
      - Snapshot URLs       (direct JPEG/PNG)
    Query param: url=<camera stream or snapshot url>
    """
    if "user" not in session:
        return "Unauthorized", 403

    if http_requests is None:
        return "requests library not installed on server", 503

    cam_url = request.args.get("url", "").strip()
    if not cam_url:
        return "Missing url parameter", 400

    try:
        resp = http_requests.get(cam_url, stream=True, timeout=5)
        content_type = resp.headers.get("Content-Type", "")

        if "multipart" in content_type:
            # MJPEG stream — read until we get one complete JPEG frame
            boundary = None
            for part in content_type.split(";"):
                part = part.strip()
                if part.startswith("boundary="):
                    boundary = part[len("boundary="):]
                    break

            buf = b""
            for chunk in resp.iter_content(chunk_size=4096):
                buf += chunk
                # Look for JPEG start/end markers
                start = buf.find(b'\xff\xd8')
                end = buf.find(b'\xff\xd9')
                if start != -1 and end != -1 and end > start:
                    jpeg = buf[start:end + 2]
                    return Response(jpeg, mimetype="image/jpeg")
                if len(buf) > 200000:
                    break
            return "Could not extract frame from MJPEG stream", 502

        else:
            # Direct image (JPEG/PNG snapshot URL)
            image_data = resp.content
            mime = content_type.split(";")[0].strip() or "image/jpeg"
            return Response(image_data, mimetype=mime)

    except Exception as e:
        return f"Camera unreachable: {str(e)}", 502


@app.route("/logout")
def logout():

    session.clear()

    response = make_response(
        redirect("/")
    )

    return response


import atexit

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
