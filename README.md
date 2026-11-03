# packet-chat-relay

PC 앱이 주고받는 TCP 트래픽을 옆에서 읽어 대화 메시지로 복원하고, 휴대폰으로 받아 보는 도구를 만들면서 정리한 저장소.

트래픽을 읽기만 함. 패킷을 보내거나 대상 프로그램의 메모리를 건드리지 않음.

실제 서비스의 프로토콜 정보, 캡처 파일, 데스크톱 앱과 웹앱 화면은 제외. 여기 있는 패킷 포맷은 예제용으로 만든 가짜 포맷.

## 바로 실행해 보기

Python만 있으면 실행 가능. 네트워크나 관리자 권한은 불필요.

```bash
python demo.py
python -m unittest discover tests
```

`demo.py`는 순서를 일부러 섞고 재전송까지 끼워 넣은 세그먼트를 파이프라인에 입력. 그래도 메시지는 원래 순서대로 출력됨.

```text
[direct/alice] ← alice: 안녕하세요
[group/team] ← bob: 패킷이 잘려도 이어 붙습니다
[direct/alice] → me: 순서가 바뀌어도 괜찮아요
```

## 데이터가 지나가는 길

```text
캡처           capture.py         대상 프로그램의 연결을 찾아 패킷 읽기
  ↓
재조립         reassembly.py      순서 복원, 중복 제거
  ↓
프레임 분리    Adapter.parse      앱마다 다른 부분
  ↓
메시지 변환    Adapter.describe   앱마다 다른 부분
  ↓
전달           pipeline.py        기록, 알림처럼 메시지를 받을 곳으로 전달
```

앱마다 달라지는 부분은 어댑터 하나뿐. 나머지 코드는 바이트 구조를 전혀 모름.

| 파일 | 역할 |
|---|---|
| `relay/capture.py` | 실시간 캡처 |
| `relay/reassembly.py` | TCP 스트림 복원 |
| `relay/adapter.py` | 어댑터 인터페이스와 공통 메시지 형식 |
| `relay/demo_adapter.py` | 예제용 가짜 포맷 |
| `relay/pipeline.py` | 위 단계를 하나로 연결 |
| `relay/records.py` | 기록 검색, 내보내기, 백업 |
| `relay/devices.py` | 휴대폰 등록 |
| `relay/webpush.py` | 잠금 화면 알림 |

## 실제 트래픽에 붙이려면

1. `relay/adapter.py`의 `parse`와 `describe` 구현. 예제는 `relay/demo_adapter.py` 참고.
2. `pip install -r requirements.txt`로 의존성 설치.
3. Windows라면 [Npcap](https://npcap.com) 설치 후 관리자 권한으로 실행.

자신에게 권한이 있는 트래픽에만 사용. 대상 서비스의 약관과 관련 법령을 먼저 확인할 것.
