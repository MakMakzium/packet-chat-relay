"""TCP 세그먼트를 원래 순서의 바이트 스트림으로 복원.

다음에 올 시퀀스 번호를 기억해 두고, 순서가 맞는 데이터만 내보냄.
먼저 도착한 뒷부분은 앞부분이 올 때까지 잠시 보관.
"""
from __future__ import annotations

from typing import Callable

SEQ_SPACE = 1 << 32
MAX_PENDING_SEGMENTS = 256
MAX_BUFFER = 1 << 20


def seq_delta(a: int, b: int) -> int:
    """a가 b보다 얼마나 앞서는지 계산. 시퀀스 번호가 2^32에서 0으로 돌아가는 경우도 처리."""
    d = (a - b) % SEQ_SPACE
    return d - SEQ_SPACE if d >= SEQ_SPACE // 2 else d


def is_stream_probe(flags: int, payload: bytes) -> bool:
    """keep-alive나 zero-window 프로브인지 확인.

    PSH 플래그 없이 0으로 채운 짧은 페이로드가 여기에 해당.
    데이터로 받아들이면 시퀀스 번호가 앞서 나가서 다음 프레임의 앞부분이 잘림.
    """
    PSH = 0x08
    return not (flags & PSH) and len(payload) <= 6 and not payload.strip(b"\x00")


class FlowBuffer:
    """한 방향의 TCP 스트림을 순서대로 복원."""

    def __init__(self) -> None:
        self.expected: int | None = None
        self.pending: dict[int, bytes] = {}

    def reset(self, seq: int) -> None:
        self.expected = seq
        self.pending.clear()

    def push(self, seq: int, payload: bytes) -> bytes:
        """세그먼트를 넣고, 이번에 순서가 확정된 바이트를 반환."""
        if self.expected is None:
            self.expected = seq
        d = seq_delta(seq, self.expected)
        if d < 0:
            # 재전송인 경우. 이미 받은 앞부분을 잘라 내고 새로운 부분만 사용.
            if -d >= len(payload):
                return b""
            payload, seq = payload[-d:], self.expected
        elif d > 0:
            # 앞부분이 아직 안 온 경우. 도착할 때까지 보관.
            self.pending[seq] = payload
            if len(self.pending) > MAX_PENDING_SEGMENTS:
                # 빠진 조각이 끝내 오지 않는 경우. 빈 곳을 건너뛰고 가장 앞선 조각부터 연결.
                earliest = min(self.pending, key=lambda s: seq_delta(s, self.expected))
                self.expected = earliest
                return self.push(earliest, self.pending.pop(earliest))
            return b""
        out = bytearray(payload)
        self.expected = (seq + len(payload)) % SEQ_SPACE
        while self.pending:
            nxt = next((s for s in self.pending if seq_delta(s, self.expected) <= 0), None)
            if nxt is None:
                break
            seg = self.pending.pop(nxt)
            overlap = -seq_delta(nxt, self.expected)
            if overlap < len(seg):
                out += seg[overlap:]
                self.expected = (nxt + len(seg)) % SEQ_SPACE
        return bytes(out)


class StreamDecoder:
    """FlowBuffer로 순서를 맞춘 뒤 파서를 실행해 완성된 프레임만 반환."""

    def __init__(self, parse: Callable[[bytes, bool], tuple[list, int]]) -> None:
        self._flow = FlowBuffer()
        self._buf = b""
        self._parse = parse

    def feed(self, seq: int, payload: bytes) -> list:
        self._buf += self._flow.push(seq, payload)
        if len(self._buf) > MAX_BUFFER:
            self._buf = self._buf[-MAX_BUFFER // 2:]
        return self._drain(False)

    def flush(self) -> list:
        """새 데이터가 한동안 없을 때 버퍼에 남은 데이터를 처리."""
        return self._drain(True)

    def _drain(self, flush: bool) -> list:
        packets, consumed = self._parse(self._buf, flush)
        self._buf = self._buf[consumed:]
        return packets
