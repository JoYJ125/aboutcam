import cv2
import datetime
import requests
import threading
import os
import json
from flask import Flask, render_template, request, jsonify, Response
import config

app = Flask(__name__, template_folder='.')

# [설정] 디스코드 웹훅 URL (본인의 주소로 변경하세요)
DISCORD_WEBHOOK_URL = config.DISCORD_WEBHOOK_URL

# 시스템 상태 및 제어용 변수
system_status = {
    "motion_detection": False,
    "ip_monitoring": False
}

# 백그라운드 모션 감지 스레드용 객체
motion_thread = None
stop_event = threading.Event()

# 스트리밍용 글로벌 프레임 변수 (웹 화면에 쏴줄 용도)
output_frame = None
frame_lock = threading.Lock()

# 녹화 파일 저장 폴더 생성
RECORD_DIR = "recordings"
if not os.path.exists(RECORD_DIR):
    os.makedirs(RECORD_DIR)

KNOWN_IPS_FILE = "known_ips.json"
known_ips_lock = threading.Lock()

def load_known_ips():
    try:
        with open(KNOWN_IPS_FILE, "r", encoding="utf-8") as f:
            return set(json.load(f))
    except (FileNotFoundError, ValueError):
        return set()

known_ips = load_known_ips()

def save_known_ips():
    with open(KNOWN_IPS_FILE, "w", encoding="utf-8") as f:
        json.dump(sorted(known_ips), f)

def get_client_ip():
    """터널(Cloudflare 등)을 거치면 remote_addr가 루프백이므로 그때만 프록시 헤더를 신뢰"""
    remote = request.remote_addr
    if remote in ("127.0.0.1", "::1"):
        forwarded = request.headers.get("CF-Connecting-IP") or request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return remote

def send_new_ip_alert(ip, user_agent):
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    message = f"🆕 **[새 IP 접속]** 처음 보는 IP가 접속했습니다.\nIP: `{ip}`\n시간: {now}\n기기: {user_agent[:100]}"
    try:
        requests.post(DISCORD_WEBHOOK_URL, json={"content": message}, timeout=5)
    except Exception as e:
        print(f"디스코드 전송 에러: {e}")

@app.before_request
def check_new_ip():
    if not system_status["ip_monitoring"]:
        return
    ip = get_client_ip()
    with known_ips_lock:
        if ip in known_ips:
            return
        known_ips.add(ip)
        save_known_ips()
    print(f"[IP 감시] 새 IP 감지: {ip}")
    threading.Thread(target=send_new_ip_alert,
                     args=(ip, request.headers.get("User-Agent", "unknown")),
                     daemon=True).start()

def motion_detection_worker():
    """웹 대시보드와 연동된 백그라운드 모션 감지, 스트리밍, 30초 알림(텍스트만) 및 5분 고정 자동 녹화 함수"""
    global output_frame
    cap = cv2.VideoCapture(0)
    
    if not cap.isOpened():
        print("[모션 감지] 웹캠을 열 수 없습니다.")
        system_status["motion_detection"] = False
        return

    print("[모션 감지] 백그라운드 모니터링 시작됨...")
    
    ret, frame1 = cap.read()
    if not ret:
        cap.release()
        system_status["motion_detection"] = False
        return

    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    fps = 20.0
    frame_width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    frame_height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))

    out = None
    is_recording = False
    recording_end_time = datetime.datetime.min
    last_alert_time = datetime.datetime.min

    # [설정] 움직임 감지 시 최소 녹화 유지 시간 (300초 = 5분)
    RECORD_DURATION_SECONDS = 300 

    while system_status["motion_detection"] and not stop_event.is_set():
        ret, frame2 = cap.read()
        if not ret:
            break

        gray1 = cv2.cvtColor(frame1, cv2.COLOR_BGR2GRAY)
        gray1 = cv2.GaussianBlur(gray1, (21, 21), 0)

        gray2 = cv2.cvtColor(frame2, cv2.COLOR_BGR2GRAY)
        gray2 = cv2.GaussianBlur(gray2, (21, 21), 0)

        diff = cv2.absdiff(gray1, gray2)
        thresh = cv2.threshold(diff, 40, 255, cv2.THRESH_BINARY)[1]
        thresh = cv2.dilate(thresh, None, iterations=2)

        contours, _ = cv2.findContours(thresh.copy(), cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

        motion_detected = False
        for contour in contours:
            if cv2.contourArea(contour) < 3000:
                continue
            
            motion_detected = True
            (x, y, w, h) = cv2.boundingRect(contour)
            cv2.rectangle(frame2, (x, y), (x + w, y + h), (0, 255, 0), 2)

        current_time = datetime.datetime.now()
        timestamp_str = current_time.strftime("%Y%m%d_%H%M%S")

        if motion_detected:
            # 움직임이 감지되면 녹화 종료 예정 시간을 현재로부터 5분 뒤로 연장
            recording_end_time = current_time + datetime.timedelta(seconds=RECORD_DURATION_SECONDS)

            if not is_recording:
                is_recording = True
                record_filename = os.path.join(RECORD_DIR, f"motion_{timestamp_str}.mp4")
                out = cv2.VideoWriter(record_filename, fourcc, fps, (frame_width, frame_height))
                print(f"[녹화 시작] 파일 저장: {record_filename} (5분간 유지)")

            # 30초 주기 디스코드 알림 전송 (텍스트 메시지만 전송)
            if (current_time - last_alert_time).total_seconds() >= 30:
                print(f"[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] 🚨 움직임 지속 감지! 디스코드 알림 전송 중...")
                alert_message = f"🚨 **[보안 경고]** 움직임이 감지되어 5분 녹화가 진행 중입니다! ({current_time.strftime('%Y-%m-%d %H:%M:%S')})"
                
                try:
                    requests.post(DISCORD_WEBHOOK_URL, json={"content": alert_message})
                except Exception as e:
                    print(f"디스코드 전송 에러: {e}")
                
                last_alert_time = current_time

        # 녹화 중이고, 설정한 5분 유지 시간이 지났다면 녹화 종료
        if is_recording:
            if out is not None:
                out.write(frame2)
            
            if current_time > recording_end_time:
                is_recording = False
                if out is not None:
                    out.release()
                    out = None
                print("[녹화 종료] 5분 녹화 시간이 완료되어 안전하게 저장되었습니다.")

        # 웹 브라우저 실시간 송출용 프레임 저장
        with frame_lock:
            output_frame = frame2.copy()

        frame1 = frame2
        cv2.waitKey(30)

    if out is not None:
        out.release()

    cap.release()
    with frame_lock:
        output_frame = None
    print("[모션 감지] 백그라운드 모니터링 종료됨.")

def generate_frames():
    global output_frame
    while True:
        with frame_lock:
            if output_frame is None:
                continue
            success, encoded_image = cv2.imencode('.jpg', output_frame)
            if not success:
                continue
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + bytearray(encoded_image) + b'\r\n')

@app.route('/')
def index():
    return render_template('index.html', status=system_status)

@app.route('/video_feed')
def video_feed():
    return Response(generate_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/toggle', methods=['POST'])
def toggle_feature():
    global motion_thread, stop_event
    data = request.json
    feature = data.get('feature')
    
    if feature == 'motion_detection':
        current_state = system_status["motion_detection"]
        
        if not current_state:
            system_status["motion_detection"] = True
            stop_event.clear()
            motion_thread = threading.Thread(target=motion_detection_worker)
            motion_thread.daemon = True
            motion_thread.start()
        else:
            system_status["motion_detection"] = False
            stop_event.set()
            
        return jsonify({"success": True, "status": system_status["motion_detection"]})
        
    elif feature == 'ip_monitoring':
        system_status["ip_monitoring"] = not system_status["ip_monitoring"]
        if system_status["ip_monitoring"]:
            # 감시를 켠 본인 IP는 알림 없이 신뢰 목록에 등록
            with known_ips_lock:
                known_ips.add(get_client_ip())
                save_known_ips()
        return jsonify({"success": True, "status": system_status["ip_monitoring"]})
    
    return jsonify({"success": False, "message": "잘못된 요청입니다."}), 400

if __name__ == '__main__':
    app.run(debug=True, port=5000)