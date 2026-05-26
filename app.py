from flask import Flask, render_template, request, redirect, session, Response, make_response, jsonify
from database import get_connection
from datetime import datetime, timedelta
import uuid
import threading
import blocker
import detector

app = Flask(__name__)
app.secret_key = "Group7_netad"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)


latest_frame = None
frame_lock = threading.Lock()

def _make_placeholder_frame():
    """Generate a black 'NO SIGNAL' JPEG used when no webcam frame is available."""
    try:
        from PIL import Image, ImageDraw
        img = Image.new("RGB", (1280, 720), color=(6, 14, 24))
        draw = ImageDraw.Draw(img)
        # Draw centered text
        text = "NO SIGNAL"
        bbox = draw.textbbox((0, 0), text)
        tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
        draw.text(((1280 - tw) // 2, (720 - th) // 2), text, fill=(30, 58, 95))
        import io
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=60)
        return buf.getvalue()
    except Exception:
        # Minimal valid 1x1 black JPEG fallback
        return (
            b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
            b'\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t'
            b'\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a'
            b'\x1f\x1e\x1d\x1a\x1c\x1c $.\' ",#\x1c\x1c(7),01444\x1f\'9=82<.342\x1e\x1f'
            b'-=49=\x17\x18\x18\x18\x18\x18\x18\x18\x18\x18\x18\x18\x18\x18'
            b'\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00\xff\xc4\x00'
            b'\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\xff\xc4\x00'
            b'\xb5\x10\x00\x02\x01\x03\x03\x02\x04\x03\x05\x05\x04\x04\x00\x00'
            b'\x01}\x01\x02\x03\x00\x04\x11\x05\x12!1A\x06\x13Qa\x07"q\x142\x81'
            b'\x91\xa1\x08#B\xb1\xc1\x15R\xd1\xf0$3br\x82\t\n\x16\x17\x18\x19'
            b'\x1a%&\'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz\x83\x84\x85\x86'
            b'\x87\x88\x89\x8a\x92\x93\x94\x95\x96\x97\x98\x99\x9a\xa2\xa3\xa4'
            b'\xa5\xa6\xa7\xa8\xa9\xaa\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xc2'
            b'\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9'
            b'\xda\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xf1\xf2\xf3\xf4\xf5'
            b'\xf6\xf7\xf8\xf9\xfa\xff\xda\x00\x08\x01\x01\x00\x00?\x00\xfb\xd2'
            b'\x8a(\x03\xff\xd9'
        )

PLACEHOLDER_FRAME = _make_placeholder_frame()

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
            response = make_response(redirect("/dashboard"))
            response.set_cookie("device_id", device_id, max_age=60*60*24*365, httponly=True, samesite="Lax")
            return response

        save_log(device_id, f"Login Failed: {username}", "FAILED")
        detector.register_failed_attempt(device_id)

        if detector.detect_attack(device_id):
            blocker.block_device(device_id, "Brute force detected")
            save_log(device_id, "Brute Force Detected", "ALERT")
            save_log(device_id, "DEVICE BLOCKED", "BLOCKED")
            return "Security Alert: Device Blocked.", 403

        response = make_response(render_template("login.html", error="Invalid username or password."))
        response.set_cookie("device_id", device_id, max_age=60*60*24*365, httponly=True, samesite="Lax")
        return response

    response = make_response(render_template("login.html"))
    response.set_cookie("device_id", device_id, max_age=60*60*24*365, httponly=True, samesite="Lax")
    return response


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

    cursor.execute("SELECT COUNT(*) FROM blocked_devices")
    unique_attackers = cursor.fetchone()[0]

    cursor.execute("SELECT device_id, event_type, status, created_at FROM security_logs ORDER BY created_at DESC LIMIT 7")
    recent_alerts = cursor.fetchall()

    conn.close()

    return render_template("dashboard.html", user=session["user"],
        today_access=today_access, unauthorized=unauthorized,
        unique_attackers=unique_attackers, recent_alerts=recent_alerts)


# ─── FEATURE 1: Real-time stats API for alert polling ───────────────────────
@app.route("/api/stats")
def api_stats():
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 403

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE status='FAILED' AND created_at >= CURRENT_DATE")
    failed_today = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE status='SUCCESS' AND created_at >= CURRENT_DATE")
    success_today = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM blocked_devices")
    blocked = cursor.fetchone()[0]

    # Last event for change detection
    cursor.execute("SELECT event_type, status, created_at FROM security_logs ORDER BY created_at DESC LIMIT 1")
    last = cursor.fetchone()

    conn.close()

    return jsonify({
        "failed_today": failed_today,
        "success_today": success_today,
        "blocked": blocked,
        "last_event": {
            "type": last[0] if last else None,
            "status": last[1] if last else None,
            "time": last[2].isoformat() if last else None
        }
    })


# ─── FEATURE 3: Block device directly from threat logs ──────────────────────
@app.route("/block-device", methods=["POST"])
def block_device_route():
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 403

    device_id = request.json.get("device_id")
    if not device_id:
        return jsonify({"error": "no device_id provided"}), 400

    blocker.block_device(device_id, "Manually blocked by admin")
    save_log(device_id, "Manually Blocked by Admin", "BLOCKED")

    return jsonify({"success": True, "device_id": device_id})


@app.route("/live-cctv")
def live_cctv():
    if "user" not in session:
        return redirect("/")
    return render_template("live_cctv.html", user=session["user"])


# ─── FEATURE 2: Threat logs with filter + search ────────────────────────────
@app.route("/threat-logs")
def threat_logs():
    if "user" not in session:
        return redirect("/")

    status_filter = request.args.get("status", "ALL")
    search_query = request.args.get("search", "").strip()

    conn = get_connection()
    cursor = conn.cursor()

    query = "SELECT device_id, event_type, status, created_at FROM security_logs WHERE 1=1"
    params = []

    if status_filter != "ALL":
        query += " AND status = %s"
        params.append(status_filter)

    if search_query:
        query += " AND (device_id ILIKE %s OR event_type ILIKE %s)"
        params.extend([f"%{search_query}%", f"%{search_query}%"])

    query += " ORDER BY created_at DESC LIMIT 100"

    cursor.execute(query, params)
    logs = cursor.fetchall()
    conn.close()

    return render_template("threat_logs.html", user=session["user"],
        logs=logs, status_filter=status_filter, search_query=search_query)


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

    cursor.execute("SELECT COUNT(*) FROM blocked_devices")
    blocked_count = cursor.fetchone()[0]

    conn.close()

    return render_template("analytics.html", user=session["user"],
        success_count=success_count, failed_count=failed_count, blocked_count=blocked_count)


@app.route("/upload_frame", methods=["POST"])
def upload_frame():
    global latest_frame
    data = request.data
    with frame_lock:
        latest_frame = data
    return "OK", 200


def generate_frames():
    import time
    global latest_frame
    last_frame = None
    while True:
        with frame_lock:
            frame = latest_frame
        if frame is None:
            # No webcam frame yet — send placeholder so the <img> renders immediately
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + PLACEHOLDER_FRAME + b'\r\n')
            time.sleep(0.5)
            continue
        if frame is last_frame:
            time.sleep(0.03)
            continue
        last_frame = frame
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')


@app.route("/video_feed")
def video_feed():
    if "user" not in session:
        return "Unauthorized", 403
    return Response(generate_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')


@app.route("/logout")
def logout():
    session.clear()
    return make_response(redirect("/"))


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
