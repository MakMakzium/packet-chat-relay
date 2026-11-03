"""세그먼트를 메시지로 변환해 받을 곳(sink)마다 전달."""
from __future__ import annotations

import threading
from typing import Callable, Iterable

from .adapter import Adapter, Message
from .reassembly import StreamDecoder, is_stream_probe

Sink = Callable[[Message], None]
FlowKey = tuple


class Pipeline:
    def __init__(self, adapter: Adapter, sinks: Iterable[Sink]) -> None:
        self.adapter = adapter
        self.sinks = list(sinks)
        self.decoders: dict[FlowKey, StreamDecoder] = {}
        self.lock = threading.Lock()

    def feed(self, flow: FlowKey, seq: int, payload: bytes, tcp_flags: int = 0x18) -> None:
        """TCP 세그먼트 하나를 입력.

        flow 형식은 (보낸 IP, 보낸 포트, 받은 IP, 받은 포트). 방향을 나눠야 양쪽 데이터가 섞이지 않음.
        """
        if not payload or is_stream_probe(tcp_flags, payload):
            return
        with self.lock:
            decoder = self.decoders.get(flow)
            if decoder is None:
                decoder = self.decoders[flow] = StreamDecoder(self.adapter.parse)
            frames = decoder.feed(seq, payload)
        self._emit(frames)

    def flush(self) -> None:
        """한동안 새 데이터가 없을 때 호출. 버퍼에 남은 데이터를 처리."""
        with self.lock:
            frames = [frame for decoder in self.decoders.values() for frame in decoder.flush()]
        self._emit(frames)

    def reset(self) -> None:
        """캡처 대상이 바뀌면 호출. 이전 연결의 상태를 삭제."""
        with self.lock:
            self.decoders.clear()

    def _emit(self, frames: list) -> None:
        for frame in frames:
            message = self.adapter.describe(frame)
            if message is None:
                continue
            for sink in self.sinks:
                sink(message)
