from flask import Flask, render_template, request, redirect, session, Response, make_response
from database import get_connection
from datetime import datetime, timedelta
import uuid
import os
import requests
import blocker
import detector
import time
import json
import queue
import threading

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

CCTV_STREAM_URL = os.getenv("CCTV_STREAM_URL")

# ---------------------------------------------------------------------------
# SSE broadcaster — thread-safe fan-out to all connected clients
# ---------------------------------------------------------------------------
_sse_lock = threading.Lock()
_sse_clients: list[queue.Queue] = []


def _broadcast(event_type: str, data: dict):
    """Push a JSON event to every connected SSE client."""
    payload = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
    with _sse_lock:
        dead = []
        for q in _sse_clients:
            try:
                q.put_nowait(payload)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sse_clients.remove(q)


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

        # Broadcast the new log entry to all SSE subscribers
        _broadcast("new_log", {
            "device_id": device_id,
            "event_type": event_type,
            "status": status,
            "created_at": philippines_time.strftime("%b %d, %Y | %I:%M:%S %p"),
            "date_only": philippines_time.strftime("%b %d, %Y"),
            "time_only": philippines_time.strftime("%I:%M:%S %p"),
        })

        # Also broadcast updated summary counts for the dashboard
        _broadcast_counts(conn)

    except:
        conn.rollback()
    finally:
        conn.close()


def _broadcast_counts(existing_conn=None):
    """Fetch live counts and push them to all SSE clients."""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM security_logs WHERE status='SUCCESS' AND created_at >= CURRENT_DATE")
        today_access = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM security_logs WHERE status='FAILED' AND created_at >= CURRENT_DATE")
        unauthorized = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM blocked_devices")
        blocked = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM security_logs WHERE status='SUCCESS'")
        success_all = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM security_logs WHERE status='FAILED'")
        failed_all = cursor.fetchone()[0]

        conn.close()

        _broadcast("counts", {
            "today_access": today_access,
            "unauthorized": unauthorized,
            "unique_attackers": blocked,
            "success_count": success_all,
            "failed_count": failed_all,
            "blocked_count": blocked,
        })
    except Exception as e:
        print(f"[SSE] count broadcast error: {e}")


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
            SELECT username
            FROM users
            WHERE username = %s
            AND password = crypt(%s, password)
        """, (username, password))

        user = cursor.fetchone()
        conn.close()

        if user:
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

    return render_template("login.html")

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


# ---------------------------------------------------------------------------
# SSE endpoint — clients connect here and receive a stream of events
# ---------------------------------------------------------------------------
@app.route("/stream")
def stream():
    if "user" not in session:
        return "Unauthorized", 403

    client_queue: queue.Queue = queue.Queue(maxsize=50)

    with _sse_lock:
        _sse_clients.append(client_queue)

    def event_stream():
        # Send a heartbeat immediately so the browser knows the connection is live
        yield ": connected\n\n"
        try:
            while True:
                try:
                    # Block up to 20 s, then send a keepalive comment
                    msg = client_queue.get(timeout=20)
                    yield msg
                except queue.Empty:
                    yield ": keepalive\n\n"
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                try:
                    _sse_clients.remove(client_queue)
                except ValueError:
                    pass

    return Response(
        event_stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx buffering if behind proxy
        }
    )


def generate_frames():
    if not CCTV_STREAM_URL:
        print("Error: CCTV_STREAM_URL is not set.")
        return

    try:
        with requests.get(CCTV_STREAM_URL, stream=True, timeout=30) as response:
            for chunk in response.iter_content(chunk_size=4096):
                if chunk:
                    yield chunk
    except Exception as e:
        print(f"Error streaming from CCTV: {e}")


@app.route("/video_feed")
def video_feed():
    if "user" not in session:
        return "Unauthorized", 403

    try:
        head = requests.head(CCTV_STREAM_URL, timeout=5)
        content_type = head.headers.get('Content-Type', 'multipart/x-mixed-replace; boundary=frame')
    except:
        content_type = 'multipart/x-mixed-replace; boundary=frame'

    return Response(generate_frames(), mimetype=content_type)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
