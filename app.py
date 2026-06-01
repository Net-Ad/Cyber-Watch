from flask import Flask, render_template, request, redirect, session, Response, make_response
from database import get_connection
from datetime import datetime, timedelta
import uuid
import os
import requests
import blocker
import detector

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

CCTV_STREAM_URL = os.getenv("CCTV_STREAM_URL")
if CCTV_STREAM_URL:
    CCTV_STREAM_URL = CCTV_STREAM_URL.strip('"').strip("'").strip()


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
        SELECT COUNT(*) FROM security_logs WHERE status='SUCCESS'
    """)
    success_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM security_logs WHERE status='FAILED'
    """)
    failed_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM blocked_devices
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


def generate_frames():
    if not CCTV_STREAM_URL:
        print("[CCTV ERROR] No stream target configured in environment.")
        return

    print(f"[CCTV INFO] Targeting stream: {CCTV_STREAM_URL}")
    
    try:
        response = requests.get(CCTV_STREAM_URL, stream=True, timeout=15)
        for chunk in response.iter_content(chunk_size=4096):
            if chunk:
                yield chunk
    except Exception as e:
        print(f"[CCTV ERROR] Failed streaming from backend source: {e}")


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


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
