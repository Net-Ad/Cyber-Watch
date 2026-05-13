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

        cursor.execute("""
            SELECT username, password
            FROM users
            WHERE username=%s
        """, (username,))

        user = cursor.fetchone()

        conn.close()

        # SUCCESS LOGIN
        if user and user[1] == password:

            session.permanent = True
            session["user"] = username

            detector.clear_failed_attempts(device_id)

            save_log(
                device_id,
                f"Login Success: {username}",
                "SUCCESS"
            )

            response = make_response(
                redirect("/dashboard")
            )

            response.set_cookie(
                "device_id",
                device_id,
                max_age=60 * 60 * 24 * 365,
                httponly=True,
                samesite="Lax"
            )

            return response

        # FAILED LOGIN
        save_log(
            device_id,
            f"Login Failed: {username}",
            "FAILED"
        )

        detector.register_failed_attempt(device_id)

        if detector.detect_attack(device_id):

            blocker.block_device(
                device_id,
                "Brute force detected"
            )

            save_log(
                device_id,
                "Brute Force Detected",
                "ALERT"
            )

            save_log(
                device_id,
                "DEVICE BLOCKED",
                "BLOCKED"
            )

            return "Security Alert: Device Blocked.", 403

        response = make_response(
            render_template(
                "login.html",
                error="Invalid username or password."
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

        yield (
            b'--frame\r\n'
            b'Content-Type: image/jpeg\r\n\r\n' +
            frame_bytes +
            b'\r\n'
        )


@app.route("/video_feed")
def video_feed():

    if "user" not in session:
        return "Unauthorized", 403

    return Response(
        generate_frames(),
        mimetype='multipart/x-mixed-replace; boundary=frame'
    )


@app.route("/logout")
def logout():

    session.clear()

    response = make_response(
        redirect("/")
    )

    return response


import atexit


@atexit.register
def release_camera():
    camera.release()


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
