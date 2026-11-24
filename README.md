# TLS 키 교환과 서버 인증서의 PQC 현황 조사

OpenSSL로 TLS 연결을 맺고, 실제로 협상한 키 교환 그룹과 서버 인증서의 발급자·공개키·서명 알고리즘을 기록하는 Python 프로그램이다. 키 교환에 양자내성암호(PQC)를 사용했는지와 인증서에 어떤 서명을 사용했는지를 따로 기록한다. 판정은 각 도메인에 접속한 시점과 클라이언트가 제안한 그룹에 적용된다.

## 보고서에서 사용한 소스

- [실측 버전 1.0.1](archive/survey_tls_1.0.1.py)은 2026년 10월 30일 국내 12개 도메인 조사에 사용한 코드다.
- [재실행 버전 1.0.3](src/survey_tls.py)은 판정에 필요한 값을 검증하고, [로그 필터](src/share_tls.py)를 이용해 공개 인증서와 협상 정보만 TLS 로그에 남긴다.

## 실행

보고서의 실측 환경은 Python 3.14.7과 OpenSSL 3.6.0이다. Python 표준 라이브러리를 사용한다. 다음 예시에서는 OpenSSL 실행 파일이 PATH에 있고, 신뢰할 CA 인증서 묶음이 현재 디렉터리의 `ca-bundle.pem`에 있다고 가정한다.

```sh
python src/survey_tls.py --sites examples/sites.csv --cafile ca-bundle.pem --out results
```

[입력 CSV](examples/sites.csv)의 `domain` 열에 조사할 도메인을 한 줄에 하나씩 적는다. 실행할 때마다 새 출력 폴더나 빈 폴더를 지정한다. 실행 후 `results.csv`와 `results.json`에서 TLS 버전, 암호 스위트, 협상 그룹, 인증서 정보와 판정 근거를 확인할 수 있다.
