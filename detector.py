from database import get_connection
from datetime import datetime, timedelta

MAX_ATTEMPTS = 5

philippines_time = datetime.utcnow() + timedelta(hours=8)

def register_failed_attempt(device_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT count FROM failed_attempts WHERE device_id=%s", (device_id,))
    row = cursor.fetchone()

    if row:
        cursor.execute("""
            UPDATE failed_attempts
            SET count = count + 1,
                last_attempt = %s
            WHERE device_id = %s
        """, (philippines_time, device_id,))
    else:
        cursor.execute("""
            INSERT INTO failed_attempts (device_id, count, last_attempt)
            VALUES (%s, 1, %s)
        """, (device_id, philippines_time,))

    conn.commit()
    conn.close()


def detect_attack(device_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT count FROM failed_attempts WHERE device_id=%s", (device_id,))
    row = cursor.fetchone()

    conn.close()

    if not row:
        return False

    return row[0] >= MAX_ATTEMPTS


def clear_failed_attempts(device_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM failed_attempts WHERE device_id=%s", (device_id,))

    conn.commit()
    conn.close()

def get_failed_count(device_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT count FROM failed_attempts WHERE device_id=%s", (device_id,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else 0
