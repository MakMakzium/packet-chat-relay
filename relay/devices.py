"""휴대폰을 PC에 등록(페어링).

1. 휴대폰이 등록을 요청하면 PC 콘솔에 6자리 코드 표시.
2. 그 코드를 휴대폰에 입력하면 기기별 키 발급.
3. 키는 휴대폰의 HttpOnly 쿠키에 저장하고, 설정 파일에는 해시만 저장.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from pathlib import Path
from typing import Callable

COOKIE = "relay_device"
CODE_TTL_SEC = 300
MAX_ATTEMPTS = 5


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


class Devices:
    def __init__(self, cfg: dict, save: Callable[[], None], path: Path | None = None) -> None:
        self.cfg, self._save = cfg, save
        self.cfg.setdefault("devices", {})
        self.path = path
        self.mtime = path.stat().st_mtime if path and path.exists() else 0.0
        self.lock = threading.Lock()
        self.code: str | None = None
        self.code_expires = 0.0
        self.attempts = 0
        # 화면에 코드를 띄우고 싶을 때 쓰는 콜백. on_code(기기 이름, 코드) 형태로 호출.
        self.on_code = None

    def save(self) -> None:
        self._save()
        if self.path and self.path.exists():
            self.mtime = self.path.stat().st_mtime

    def _sync(self) -> None:
        """실행 중에 다른 프로세스가 설정 파일을 바꿨다면 기기 목록을 다시 읽음."""
        if not self.path or not self.path.exists():
            return
        m = self.path.stat().st_mtime
        if m != self.mtime:
            self.mtime = m
            try:
                devs = json.loads(self.path.read_text(encoding="utf-8")).get("devices", {})
            except ValueError:
                return
            self.cfg["devices"].clear()
            self.cfg["devices"].update(devs)

    def start_pairing(self, device_name: str) -> None:
        """새 코드를 만들어 PC 콘솔에만 표시. 코드를 휴대폰으로 보내면 인증의 의미가 없음."""
        with self.lock:
            self.code = f"{secrets.randbelow(10**6):06d}"
            self.code_expires = time.time() + CODE_TTL_SEC
            self.attempts = 0
        print(f"\n[기기 등록] '{device_name}' 등록 요청. 기기에 입력할 코드: {self.code}  (5분 유효)\n", flush=True)
        if self.on_code:
            self.on_code(device_name, self.code)

    def pair(self, code: str, device_name: str) -> str | None:
        """코드가 맞으면 새 기기 키를, 틀리면 None을 반환. 5번 틀리면 코드 폐기."""
        with self.lock:
            if not self.code or time.time() > self.code_expires:
                return None
            if not secrets.compare_digest(code.strip(), self.code):
                self.attempts += 1
                if self.attempts >= MAX_ATTEMPTS:
                    self.code = None
                    print("[기기 등록] 코드 입력 5회 실패. 코드를 폐기했습니다", flush=True)
                return None
            self.code = None
            key = secrets.token_urlsafe(32)
            dev_id = secrets.token_hex(4)
            now = int(time.time())
            self.cfg["devices"][dev_id] = {"name": device_name[:40] or "기기", "key_sha256": _hash(key),
                                           "added": now, "last_seen": now}
        self.save()
        print(f"[기기 등록] 완료: {device_name} ({dev_id})", flush=True)
        return key

    def check(self, key: str | None) -> str | None:
        """쿠키의 키가 등록된 기기의 것이면 기기 ID 반환."""
        if not key:
            return None
        self._sync()
        h = _hash(key)
        for dev_id, d in self.cfg["devices"].items():
            if secrets.compare_digest(d["key_sha256"], h):
                if time.time() - d.get("last_seen", 0) > 3600:
                    d["last_seen"] = int(time.time())
                    self.save()
                return dev_id
        return None

    def revoke(self, ident: str) -> list[str]:
        """기기 ID나 이름으로 등록을 해제하고, 해제한 ID 목록을 반환."""
        gone = [k for k, d in self.cfg["devices"].items() if ident in (k, d["name"])]
        for k in gone:
            del self.cfg["devices"][k]
        if gone:
            self.save()
        return gone

    def listing(self) -> list[str]:
        fmt = lambda t: time.strftime("%Y-%m-%d %H:%M", time.localtime(t))
        return [f"{k}  {d['name']:<16} 등록 {fmt(d['added'])}  최근 {fmt(d['last_seen'])}"
                for k, d in self.cfg["devices"].items()]
