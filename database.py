import psycopg2

DATABASE_URL = "postgresql://cctv_security_user:dQBxqR1O7maOEnZ1yakDVuN9i7XFidHi@dpg-d7utc1reo5us73dcd810-a.singapore-postgres.render.com/cctv_security"

def get_connection():
    return psycopg2.connect(DATABASE_URL)