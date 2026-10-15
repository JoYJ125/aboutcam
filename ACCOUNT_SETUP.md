# AboutCam 계정 및 Discord 연동 설정

이 브랜치는 회원가입/로그인과 계정별 Discord 웹훅을 추가합니다. 카메라 접근 권한이 있으므로 회원가입은 초대 코드가 있어야 가능합니다.

## 필수 환경변수

- `ABOUTCAM_FERNET_KEY`: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` 출력값. **키를 분실하면 기존 웹훅을 복호화할 수 없습니다.**
- `ABOUTCAM_INVITE_CODE`: 관리자만 공유하는 긴 무작위 초대 코드.
- `SECRET_KEY` 및 기존 `config.py` 설정은 현재 구조대로 유지합니다.
- `SESSION_COOKIE_SECURE=true`: HTTPS로 접속할 때 사용.
- `TRUSTED_PROXIES`: 실제 신뢰하는 리버스 프록시 IP만 쉼표로 구분.

## 실행

```bash
python -m pip install -r requirements.txt
python app.py
```

`/register`에서 아이디, 비밀번호(12자 이상), 초대 코드, Discord 채널 웹훅 URL을 입력합니다. 가입 성공 시 해당 웹훅으로 연동 메시지를 전송합니다. 이후 로그인한 계정의 새 IP 알림은 해당 계정 웹훅으로 전송됩니다. 움직임 감지 알림은 현재 공유 카메라를 사용하는 모든 등록 계정에 전송됩니다.

`users.db`는 로컬 파일이므로 안전하게 백업해야 하며 공개 저장소에 올리면 안 됩니다. Discord 웹훅 URL은 비밀정보이므로 로그나 이슈에 공유하지 마세요.

## 기존 단일 관리자 로그인

기존 `config.ADMIN_PASSWORD` 기반 로그인은 새 계정 로그인으로 대체됩니다. 처음에는 초대 코드로 새 계정을 등록하세요. 이전 관리자 비밀번호가 자동으로 계정으로 이전되지는 않습니다.

## 테스트

```bash
python -m unittest discover -s tests -v
```
