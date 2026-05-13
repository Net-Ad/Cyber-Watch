import cv2
import websocket
import time

RAILWAY_WS_URL = "wss://cyberwatch.up.railway.app/ws/stream"

def connect_and_stream():
    while True:
        try:
            print("Connecting to Railway...")
            ws = websocket.create_connection(RAILWAY_WS_URL)
            print("Connected! Streaming started.")

            cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
            cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
            cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)

            time.sleep(1)

            while True:
                ret, frame = cap.read()
                if not ret:
                    print("Failed to grab frame.")
                    break

                _, jpeg = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 50])
                ws.send_binary(jpeg.tobytes())

            cap.release()
            ws.close()

        except Exception as e:
            print(f"Error: {e}. Reconnecting in 3 seconds...")
            time.sleep(3)

connect_and_stream()