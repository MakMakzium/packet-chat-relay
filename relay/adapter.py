"""앱마다 다른 패킷 포맷을 처리하는 어댑터의 인터페이스.

파이프라인은 바이트 구조를 전혀 모름. 포맷에 관한 지식은 전부 어댑터 안에 있음.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class Message:
    """어댑터를 지난 모든 대화의 공통 형식."""
    kind: str
    room: str
    sender: str
    text: str
    outgoing: bool = False


class Adapter(Protocol):
    def parse(self, buf: bytes, flush: bool) -> tuple[list[Any], int]:
        """버퍼에서 완성된 프레임을 꺼내 (프레임 목록, 처리한 바이트 수)를 반환.

        처리한 만큼만 버퍼에서 지워짐. 덜 도착한 프레임을 세지 않으면 다음 호출 때 다시 들어옴.
        flush가 참이면 한동안 새 데이터가 없었다는 뜻. 잘린 프레임을 버려도 됨.
        """
        ...

    def describe(self, frame: Any) -> Message | None:
        """프레임을 메시지로 변환. 상태 알림처럼 대화가 아니면 None 반환."""
        ...
