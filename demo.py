"""네트워크 없이 전체 흐름을 보여 주는 데모.

    python demo.py

세그먼트를 일부러 뒤섞어 넣어도 메시지가 제대로 복원되는지 확인 가능.
"""
from __future__ import annotations

from relay.adapter import Message
from relay.demo_adapter import DemoAdapter, encode
from relay.pipeline import Pipeline


def print_message(m: Message) -> None:
    arrow = "→" if m.outgoing else "←"
    print(f"[{m.kind}/{m.room}] {arrow} {m.sender}: {m.text}")


def main() -> None:
    stream = b"".join([
        encode(kind="direct", room="alice", sender="alice", text="안녕하세요"),
        encode(state="heartbeat"),  # 대화가 아니라서 출력되지 않음.
        encode(kind="group", room="team", sender="bob", text="패킷이 잘려도 이어 붙습니다"),
        encode(kind="direct", room="alice", sender="me", text="순서가 바뀌어도 괜찮아요", outgoing=True),
    ])

    # 시퀀스 번호가 도중에 2^32를 넘어 0으로 돌아가도록 끝 가까이에서 시작.
    size = 17
    base_seq = 2**32 - 40
    segments = [((base_seq + i) % 2**32, stream[i:i + size]) for i in range(0, len(stream), size)]

    # 이웃한 세그먼트끼리 순서를 바꾸고, 하나는 재전송된 것처럼 한 번 더 넣음.
    shuffled = list(segments)
    for i in range(1, len(shuffled) - 1, 3):
        shuffled[i], shuffled[i + 1] = shuffled[i + 1], shuffled[i]
    shuffled.insert(4, segments[1])

    # 예제 주소는 문서용 예약 대역 사용.
    flow = ("198.51.100.7", 40000, "192.0.2.10", 50000)
    pipeline = Pipeline(DemoAdapter(), [print_message])
    print(f"세그먼트 {len(shuffled)}개 (순서 뒤섞임, 재전송 1개 포함)\n")
    for seq, payload in shuffled:
        pipeline.feed(flow, seq, payload)
    pipeline.flush()


if __name__ == "__main__":
    main()
