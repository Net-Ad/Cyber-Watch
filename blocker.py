<<<<<<< HEAD
from database import get_connection
from datetime import datetime, timedelta

philippines_time = datetime.utcnow() + timedelta(hours=8)

def block_device(device_id, reason="Brute force detected"):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO blocked_devices (device_id, reason, blocked_at)
        VALUES (%s, %s, %s)
        ON CONFLICT (device_id) DO UPDATE SET reason=%s
    """, (device_id, reason, philippines_time, reason, ))

    conn.commit()
    conn.close()


def is_blocked(device_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT 1 FROM blocked_devices WHERE device_id=%s", (device_id,))
    result = cursor.fetchone()

    conn.close()

    return result is not None
=======
from database import get_connection
from datetime import datetime, timedelta

philippines_time = datetime.utcnow() + timedelta(hours=8)

def block_device(device_id, reason="Brute force detected"):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO blocked_devices (device_id, reason, blocked_at)
        VALUES (%s, %s, %s)
        ON CONFLICT (device_id) DO UPDATE SET reason=%s
    """, (device_id, reason, philippines_time, reason, ))

    conn.commit()
    conn.close()


def is_blocked(device_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT 1 FROM blocked_devices WHERE device_id=%s", (device_id,))
    result = cursor.fetchone()

    conn.close()

    return result is not None
>>>>>>> 5ac76773255beb7199aedf6c80e40b0dd7579e78
