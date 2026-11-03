"""저장된 대화 기록의 검색, 내보내기, 백업, 정리.

기록은 날짜별 파일(logs/YYYY-MM-DD.jsonl)에 한 줄에 메시지 하나씩 저장.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import re
import zipfile
from datetime import datetime, timedelta
from pathlib import Path

# 내보낸 파일이 고쳐졌는지 확인하는 용도라 비밀 값이 아님. 앱마다 같은 키를 쓰므로 다른 PC에서도 확인 가능.
SIGN_KEY = b"relay-export-v1"
LOG_NAME = re.compile(r"\d{4}-\d{2}-\d{2}\.jsonl")
SIG_PREFIX = "# signature: "


def _log_files(log_dir: Path) -> list[Path]:
    return sorted(p for p in log_dir.glob("*.jsonl") if LOG_NAME.fullmatch(p.name))


def _tokens(s: str, quoted: bool = False) -> tuple[str, ...]:
    """문자열이 기록 파일에 적혀 있을 수 있는 모양을 모두 반환.

    지금은 한글을 그대로 저장하지만, 예전 파일이나 다른 도구로 만든 백업에는
    \\uXXXX 형태로 들어 있을 수 있어서 둘 다 탐색.
    """
    forms = {json.dumps(s, ensure_ascii=False), json.dumps(s)}
    return tuple(f if quoted else f[1:-1] for f in forms)


def _read(path: Path, needles: tuple[str, ...] | None = None, lower: bool = False) -> list[dict]:
    """날짜 파일 하나를 읽음.

    읽는 시간 대부분은 JSON 해석에 쓰임. needles를 주면 그 문자열이 든 줄만 해석해서 빠르게 거름.
    대략적인 필터이므로, 정확히 맞는지는 호출하는 쪽에서 다시 확인 필요.
    """
    out = []
    raw = path.read_text(encoding="utf-8")
    if needles is not None and not any(n in (raw.lower() if lower else raw) for n in needles):
        return out
    for line in raw.splitlines():
        if needles is not None and not any(n in (line.lower() if lower else line) for n in needles):
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def load_messages(log_dir: Path, *, days: int | None = None, room: str | None = None,
                  kinds: set[str] | None = None, contains: list[str] | None = None) -> list[dict]:
    """메시지를 시간순으로 읽음.

    days를 주면 오늘을 포함한 최근 며칠만 읽음.
    contains는 줄을 미리 거르는 대략적인 필터라서, 정확히 맞는지는 호출하는 쪽에서 다시 확인 필요.
    """
    files = _log_files(log_dir)
    if days is not None:
        first = (datetime.now() - timedelta(days=max(days - 1, 0))).strftime("%Y-%m-%d")
        files = [f for f in files if f.stem >= first]
    needles = (
        _tokens(room, quoted=True) if room
        else tuple(t for w in contains for t in _tokens(w)) if contains is not None
        else None
    )
    msgs = [m for f in files for m in _read(f, needles)]
    if room:
        msgs = [m for m in msgs if m.get("room") == room]
    if kinds:
        msgs = [m for m in msgs if m.get("kind") in kinds]
    return sorted(msgs, key=lambda m: m.get("ts", 0))


def load_older(log_dir: Path, room: str | set[str], before: float, limit: int = 100) -> tuple[list[dict], bool]:
    """before 이전 메시지를 최대 limit개 읽고, 더 오래된 메시지가 남았는지도 함께 반환.

    최근 파일부터 거꾸로 읽다가 limit개를 넘으면 중단.
    """
    # 같은 대화가 여러 방 키로 나뉘어 저장됐을 수 있어서 키를 여러 개 받음.
    rooms = {room} if isinstance(room, str) else set(room)
    needles = tuple(t for r in rooms for t in _tokens(r, quoted=True))
    got: list[dict] = []
    for f in reversed(_log_files(log_dir)):
        day = [m for m in _read(f, needles) if m.get("room") in rooms and m.get("ts", 0) < before]
        got = day + got
        if len(got) > limit:
            break
    got.sort(key=lambda m: m.get("ts", 0))
    return got[-limit:], len(got) > limit


def search(log_dir: Path, q: str, *, room: str | None = None, kinds: set[str] | None = None,
           limit: int = 200) -> list[dict]:
    """본문, 보낸 사람, 방 이름에서 q를 찾아 최신순으로 반환."""
    q = q.strip().lower()
    if not q:
        return []
    needles = _tokens(q)
    hits = []
    for f in reversed(_log_files(log_dir)):
        day = sorted(_read(f, needles, lower=True), key=lambda m: m.get("ts", 0), reverse=True)
        for m in day:
            if (room and m.get("room") != room) or (kinds and m.get("kind") not in kinds):
                continue
            hay = f"{m.get('text', '')}\n{m.get('sender', '')}\n{m.get('room_name') or m.get('room', '')}".lower()
            if q in hay:
                hits.append(m)
                if len(hits) >= limit:
                    return hits
    return hits


# 내보내기와 서명

def _sign(payload: str) -> str:
    return hmac.new(SIGN_KEY, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def _span(msgs: list[dict]) -> tuple[str, str]:
    if not msgs:
        return "", ""
    f = lambda t: datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")  # noqa: E731
    return f(msgs[0]["ts"]), f(msgs[-1]["ts"])


def export_text(msgs: list[dict], now: datetime | None = None) -> str:
    now = now or datetime.now()
    a, b = _span(msgs)
    lines = ["# 대화 내보내기",
             f"# 내보낸 시간: {now.strftime('%Y-%m-%d %H:%M:%S')}",
             f"# 대화 기간: {a} ~ {b}" if msgs else "# 대화 기간: -",
             f"# 메시지 수: {len(msgs)}", ""]
    for m in msgs:
        t = datetime.fromtimestamp(m["ts"]).strftime("%Y-%m-%d %H:%M:%S")
        room = m.get("room_name") or m.get("room", "")
        who = "나" if m.get("outgoing") else (m.get("sender") or "-")
        lines.append(f"[{t}] [{room}] {who}: {m.get('text', '')}".replace("\r", ""))
    body = "\n".join(lines) + "\n"
    return body + SIG_PREFIX + _sign(body) + "\n"


def export_json(msgs: list[dict], now: datetime | None = None) -> str:
    now = now or datetime.now()
    a, b = _span(msgs)
    doc = {"exported_at": (now).strftime("%Y-%m-%d %H:%M:%S"), "from": a, "to": b,
           "count": len(msgs), "messages": msgs}
    body = json.dumps(doc, ensure_ascii=False, sort_keys=True)
    return json.dumps({**doc, "signature": _sign(body)}, ensure_ascii=False, indent=1)


def export_csv(msgs: list[dict], now: datetime | None = None) -> str:
    """엑셀에서 바로 열 수 있는 표로 내보냄. 마지막 줄은 파일 확인용 서명."""
    import csv

    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["시각", "대화방", "종류", "발신자", "내가보냄", "내용"])
    for m in msgs:
        t = datetime.fromtimestamp(m["ts"]).strftime("%Y-%m-%d %H:%M:%S")
        w.writerow([t, m.get("room_name") or m.get("room", ""), m.get("kind", ""),
                    m.get("sender", ""), "Y" if m.get("outgoing") else "", m.get("text", "")])
    body = buf.getvalue()
    return body + SIG_PREFIX + _sign(body) + "\n"


EXPORTERS = {"txt": lambda m: export_text(m), "json": lambda m: export_json(m), "csv": lambda m: export_csv(m)}


def verify_export(content: str) -> bool:
    """내보낸 파일이 고쳐지지 않았는지 서명으로 확인."""
    s = content.lstrip("﻿").lstrip()
    content = content.lstrip("﻿")
    if s.startswith("{"):
        try:
            doc = json.loads(s)
        except ValueError:
            return False
        sig = doc.pop("signature", "")
        return bool(sig) and hmac.compare_digest(sig, _sign(json.dumps(doc, ensure_ascii=False, sort_keys=True)))
    idx = content.rfind(SIG_PREFIX)
    if idx < 0:
        return False
    sig = content[idx + len(SIG_PREFIX):].strip()
    return hmac.compare_digest(sig, _sign(content[:idx]))


# 백업, 복원, 정리

def backup_zip(data_dir: Path) -> bytes:
    """설정(config.json)과 모든 기록을 zip 파일 하나로 묶음."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        cfg = data_dir / "config.json"
        if cfg.exists():
            z.write(cfg, "config.json")
        for f in _log_files(data_dir / "logs"):
            z.write(f, f"logs/{f.name}")
    return buf.getvalue()


def restore_zip(data_dir: Path, data: bytes) -> dict:
    """백업을 복원. 기록은 날짜별로 합쳐 중복을 없애고, 기존 설정은 config.json.bak으로 보관."""
    stats = {"logs": 0, "config": False}
    log_dir = data_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = set(z.namelist())
        for name in sorted(names):
            # zip 안의 경로는 믿지 않음. "../" 같은 경로로 다른 곳에 쓰지 못하게 이 형식만 허용.
            m = re.fullmatch(r"logs/(\d{4}-\d{2}-\d{2}\.jsonl)", name)
            if not m:
                continue
            target = log_dir / m.group(1)
            old = _read(target) if target.exists() else []
            new = [json.loads(x) for x in z.read(name).decode("utf-8").splitlines() if x.strip().startswith("{")]
            seen, merged = set(), []
            for msg in old + new:
                key = (msg.get("ts"), msg.get("room"), msg.get("sender"), msg.get("text"))
                if key not in seen:
                    seen.add(key)
                    merged.append(msg)
            merged.sort(key=lambda x: x.get("ts", 0))
            target.write_text("".join(json.dumps(x, ensure_ascii=False) + "\n" for x in merged), encoding="utf-8")
            stats["logs"] += 1
        if "config.json" in names:
            cfg_path = data_dir / "config.json"
            if cfg_path.exists():
                (data_dir / "config.json.bak").write_bytes(cfg_path.read_bytes())
            # 설정이 깨져 있으면 여기서 예외가 나서 덮어쓰지 않음.
            json.loads(z.read("config.json"))
            cfg_path.write_bytes(z.read("config.json"))
            stats["config"] = True
    return stats


def prune_logs(log_dir: Path, days: int) -> int:
    """오늘을 포함한 최근 며칠만 남기고 삭제. 지운 파일 수를 반환."""
    cutoff = (datetime.now() - timedelta(days=max(days - 1, 0))).strftime("%Y-%m-%d")
    n = 0
    for f in _log_files(log_dir):
        if f.stem < cutoff:
            f.unlink()
            n += 1
    return n


def delete_room(log_dir: Path, room: str | set[str]) -> int:
    """대화방 하나의 메시지를 모두 삭제하고, 지운 메시지 수를 반환."""
    rooms = {room} if isinstance(room, str) else set(room)
    needles = tuple(t for r in rooms for t in _tokens(r, quoted=True))
    removed = 0
    for f in _log_files(log_dir):
        # 이 방의 메시지가 없는 날짜 파일은 다시 쓰지 않음.
        if not any(n in f.read_text(encoding="utf-8") for n in needles):
            continue
        msgs = _read(f)
        keep = [m for m in msgs if m.get("room") not in rooms]
        if len(keep) != len(msgs):
            removed += len(msgs) - len(keep)
            if keep:
                f.write_text("".join(json.dumps(m, ensure_ascii=False) + "\n" for m in keep), encoding="utf-8")
            else:
                f.unlink()
    return removed


def matcher(targets: list[tuple[float, set[str], str]]):
    """메시지가 (시각, 방 키들, 본문) 목록에 있는지 확인하는 함수를 생성.

    메시지에 별도의 ID가 없어서 셋이 모두 맞아야 같은 메시지로 판단.
    """
    index: dict[tuple, set[str]] = {}
    for ts, rooms, text in targets:
        index.setdefault((ts, text), set()).update(rooms)
    return lambda m: m.get("room") in index.get((m.get("ts"), m.get("text")), ())


def delete_messages(log_dir: Path, targets: list[tuple[float, set[str], str]]) -> int:
    """지정한 메시지를 삭제하고, 지운 수를 반환. 해당 날짜의 파일만 열람."""
    by_day: dict[str, list] = {}
    for t in targets:
        by_day.setdefault(datetime.fromtimestamp(t[0]).strftime("%Y-%m-%d"), []).append(t)
    removed = 0
    for day, items in by_day.items():
        f = log_dir / f"{day}.jsonl"
        if not f.exists():
            continue
        msgs = _read(f)
        hit = matcher(items)
        keep = [m for m in msgs if not hit(m)]
        if len(keep) != len(msgs):
            removed += len(msgs) - len(keep)
            if keep:
                f.write_text("".join(json.dumps(m, ensure_ascii=False) + "\n" for m in keep), encoding="utf-8")
            else:
                f.unlink()
    return removed
