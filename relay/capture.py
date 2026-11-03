"""실시간 캡처. 트래픽을 읽기만 하고, 패킷을 보내거나 대상 프로그램을 건드리지 않음.

Windows에서는 Npcap과 관리자 권한 필요.
scapy와 psutil은 무거워서 실제로 캡처할 때만 불러옴.
"""
from __future__ import annotations

import ipaddress
import sys
import time

from .pipeline import Pipeline

IGNORED_REMOTE_PORTS = {80, 443}
REFRESH_SEC = 10
FLUSH_IDLE_SEC = 2


def process_endpoints(process_names: list[str]) -> set[tuple[str, int]]:
    """대상 프로그램이 지금 연결 중인 원격 주소를 탐색. 서버나 포트가 바뀌어도 따라갈 수 있음."""
    import psutil

    wanted = {name.lower() for name in process_names}
    pids = {p.pid for p in psutil.process_iter(["name"]) if (p.info["name"] or "").lower() in wanted}
    if not pids:
        return set()
    return {(c.raddr.ip, c.raddr.port) for c in psutil.net_connections(kind="tcp")
            if c.pid in pids and c.status == psutil.CONN_ESTABLISHED and c.raddr
            and ipaddress.ip_address(c.raddr.ip).is_global and c.raddr.port not in IGNORED_REMOTE_PORTS}


def build_bpf(endpoints: set[tuple[str, int]], fallback_ports: list[int]) -> str:
    if endpoints:
        hosts = " or ".join(f"host {h}" for h in sorted({h for h, _ in endpoints}))
        ports = " or ".join(f"port {p}" for p in sorted({p for _, p in endpoints}))
        return f"tcp and ({hosts}) and ({ports})"
    if not fallback_ports:
        raise ValueError("대상 프로세스를 찾지 못했고 fallback_ports도 비어 있습니다")
    return "tcp and (" + " or ".join(f"port {p}" for p in fallback_ports) + ")"


def run(pipeline: Pipeline, process_names: list[str], fallback_ports: list[int] | None = None) -> None:
    """캡처를 계속 실행. 대상의 연결이 바뀌면 필터를 새로 생성."""
    # 이 두 레이어를 먼저 불러와야 함. 빠뜨리면 scapy가 링크 타입을 몰라서
    # 패킷을 날것으로 넘기고, IP와 TCP를 찾지 못해 전부 버려짐.
    import scapy.layers.inet  # noqa: F401
    import scapy.layers.l2  # noqa: F401
    from scapy.layers.inet import IP, TCP
    from scapy.sendrecv import AsyncSniffer

    def on_packet(packet) -> None:
        # 여기서 예외가 밖으로 나가면 캡처 스레드가 멈춤. 기록만 하고 다음 패킷으로 넘어감.
        try:
            if IP in packet and TCP in packet:
                tcp = packet[TCP]
                flow = (packet[IP].src, tcp.sport, packet[IP].dst, tcp.dport)
                pipeline.feed(flow, tcp.seq, bytes(tcp.payload), int(tcp.flags))
        except Exception as e:  # noqa: BLE001
            print(f"[capture] 패킷 처리 오류: {e}", file=sys.stderr, flush=True)

    sniffer, current = None, None
    while True:
        bpf = build_bpf(process_endpoints(process_names), fallback_ports or [])
        if bpf != current:
            if sniffer:
                sniffer.stop()
            pipeline.reset()
            sniffer = AsyncSniffer(filter=bpf, prn=on_packet, store=False)
            sniffer.start()
            current = bpf
            print("[capture]", bpf, flush=True)
        for _ in range(REFRESH_SEC // FLUSH_IDLE_SEC):
            time.sleep(FLUSH_IDLE_SEC)
            pipeline.flush()
