"""예제용 가짜 포맷. 실제 서비스의 프로토콜 아님.

프레임 구조: "DEMO" + 본문 길이(2바이트, 빅엔디언) + JSON 본문
"""
from __future__ import annotations

import json
import struct

from .adapter import Message

MAGIC = b"DEMO"
HEADER_LEN = len(MAGIC) + 2


def encode(**fields) -> bytes:
    body = json.dumps(fields, ensure_ascii=False).encode()
    return MAGIC + struct.pack(">H", len(body)) + body


class DemoAdapter:
    def parse(self, buf: bytes, flush: bool) -> tuple[list[dict], int]:
        frames, pos = [], 0
        while True:
            start = buf.find(MAGIC, pos)
            if start < 0:
                # 프레임 시작을 찾지 못한 경우. 끝부분이 잘린 "DEM"일 수 있어 그만큼은 남겨 둠.
                keep = 0 if flush else min(len(buf) - pos, len(MAGIC) - 1)
                return frames, len(buf) - keep
            if len(buf) - start < HEADER_LEN:
                return frames, len(buf) if flush else start
            size = struct.unpack_from(">H", buf, start + len(MAGIC))[0]
            end = start + HEADER_LEN + size
            if end > len(buf):
                # 본문이 아직 덜 도착한 경우. 다음 세그먼트를 기다림.
                return frames, len(buf) if flush else start
            try:
                frames.append(json.loads(buf[start + HEADER_LEN:end]))
                pos = end
            except ValueError:
                # 본문이 깨졌다면 길이도 믿을 수 없음. 시작 표시 바로 다음부터 다시 탐색.
                pos = start + len(MAGIC)

    def describe(self, frame: dict) -> Message | None:
        if "text" not in frame:
            return None
        return Message(kind=frame.get("kind", "chat"), room=frame.get("room", "general"),
                       sender=frame.get("sender", "?"), text=frame["text"],
                       outgoing=bool(frame.get("outgoing")))
