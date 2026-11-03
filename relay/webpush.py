"""홈 화면에 추가한 웹앱(PWA)으로 잠금 화면 알림을 전송.

알림은 PC에서 Apple이나 Google의 푸시 서버를 거쳐 휴대폰으로 전달됨.
그래서 휴대폰이 PC와 다른 네트워크에 있어도 받을 수 있음. 구독은 HTTPS 페이지에서만 만들 수 있음.

VAPID 키는 처음 실행할 때 만들어 data_dir/vapid.json에 저장.
구독은 기기별로 설정에 저장하고, 등록을 해제한 기기에는 보내지 않음.
"""
from __future__ import annotations

import base64
import json
import threading
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class WebPush:
    def __init__(self, data_dir: Path, cfg: dict, save: Callable[[], None]) -> None:
        self.cfg, self.save = cfg, save
        # 형식: {기기 ID: 구독 정보}
        self.cfg.setdefault("push_subs", {})
        self.lock = threading.Lock()
        path = data_dir / "vapid.json"
        if path.exists():
            keys = json.loads(path.read_text(encoding="utf-8"))
        else:
            key = ec.generate_private_key(ec.SECP256R1())
            pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()).decode()
            pub = key.public_key().public_bytes(serialization.Encoding.X962,
                                                serialization.PublicFormat.UncompressedPoint)
            keys = {"private_pem": pem, "public": _b64url(pub)}
            path.write_text(json.dumps(keys), encoding="utf-8")
        self.private_pem = keys["private_pem"]
        self.public_key = keys["public"]

    # 구독 관리

    def subscribe(self, dev_id: str, sub: dict) -> None:
        if not isinstance(sub, dict) or not str(sub.get("endpoint", "")).startswith("https://"):
            raise ValueError("bad subscription")
        with self.lock:
            self.cfg["push_subs"][dev_id] = {"endpoint": sub["endpoint"], "keys": sub.get("keys", {})}
        self.save()

    def unsubscribe(self, dev_id: str) -> None:
        with self.lock:
            gone = self.cfg["push_subs"].pop(dev_id, None)
        if gone:
            self.save()

    def subscribed(self, dev_id: str) -> bool:
        return dev_id in self.cfg["push_subs"]

    # 알림 보내기

    def send(self, title: str, body: str, room: str, badge: int | None = None,
             ts: float | None = None, skip=()) -> None:
        """등록된 기기로 알림을 전송.

        badge는 앱 아이콘에 표시할 안 읽은 수, ts는 알림을 눌렀을 때 찾아갈 메시지의 시각.
        skip에는 지금 앱을 보고 있는 기기를 지정. 이미 화면에 보이므로 알림을 보내지 않음.
        """
        with self.lock:
            targets = {d: s for d, s in self.cfg["push_subs"].items()
                       if d in self.cfg.get("devices", {}) and d not in skip}
        if targets:
            d = {"title": title, "body": body[:300], "room": room}
            if badge is not None:
                d["badge"] = badge
            if ts is not None:
                d["ts"] = ts
            payload = json.dumps(d, ensure_ascii=False)
            threading.Thread(target=self._send_all, args=(targets, payload), daemon=True).start()

    def _send_all(self, targets: dict, payload: str) -> None:
        from pywebpush import WebPushException, webpush

        dead = []
        for dev_id, sub in targets.items():
            try:
                webpush(sub, payload, vapid_private_key=self._vapid(),
                        vapid_claims={"sub": self.cfg.get("push_contact") or "mailto:relay@example.com"},
                        ttl=3600, timeout=10)
            except WebPushException as e:
                code = getattr(e.response, "status_code", None)
                # 404와 410은 구독 만료를 뜻하므로 삭제.
                if code in (404, 410):
                    dead.append(dev_id)
                print(f"[webpush] {dev_id} 실패: {code} {e}", flush=True)
            except Exception as e:  # noqa: BLE001
                # 네트워크 오류 같은 일시적인 실패. 구독은 그대로 두고 다음 메시지 때 다시 전송.
                print(f"[webpush] {dev_id} 실패: {e}", flush=True)
        for d in dead:
            self.unsubscribe(d)

    def _vapid(self):
        # Apple 푸시 서버가 요구하는 RFC 8292 형식을 쓰려면 Vapid02가 필요함.
        from py_vapid import Vapid02

        return Vapid02.from_pem(self.private_pem.encode())
