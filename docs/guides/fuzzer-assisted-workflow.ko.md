# Fuzzer 설정 보조 기능 사용법

## 빈 화면에서 직접 시작하기

캡처한 요청이 없어도 시작할 수 있다. `Request`에는 URL만 넣는 것이 아니라 **요청 줄과 Host 헤더가 있는 raw HTTP 요청**을 넣는다. example.com은 입력 형식과 미리보기 설명용이다. 실제 실행 때는 본인 소유이거나 테스트 허가를 받은 대상 주소로 바꾼다.

1. `Request`에 다음 두 줄을 붙여 넣는다.

   ```http
   GET /?q=demo HTTP/1.1
   Host: example.com
   ```

2. 요청의 `demo`만 선택하고 요청 위의 `Add §`를 누른다. `q=§demo§`가 되면 이 위치를 payload로 바꾼다는 뜻이다. `Undo`로 마지막 표시 작업을 되돌릴 수 있다.
3. `Payloads`에 다음처럼 한 줄에 하나씩 넣는다.

   ```text
   alpha
   beta
   ```

4. 상단에 `1 position`, `2 payloads → 2 planned requests`가 나타나는지 확인한다. 처음 직접 작성한 위 요청은 `HTTPS`, 연결 대상은 `https://example.com:443`이다. HTTP가 필요하면 `Transport`에서 `HTTP`를 선택한다. 대상은 `http://example.com:80`으로 바뀌며 요청의 표시와 payload는 그대로 남는다. Host에 포트를 직접 썼다면 그 포트는 유지된다.
5. `Preview & details`를 펼치고 첫 샘플을 연다. 요청 줄이 `GET /?q=alpha HTTP/1.1`로 바뀌는 것을 확인한다. 미리보기는 전송하지 않는다. 실제 실행은 허가된 대상, 연결 주소와 포트, HTTP 버전, 계획 요청 수를 확인한 뒤에만 `Start`로 시작한다.

`Start`가 비활성화되어 있으면 옆 안내를 확인한다.

- `Paste a raw HTTP request…`: 아직 요청이 없다. 위 형식으로 붙여 넣거나 History / Replay에서 가져온다.
- `Invalid request line in editor`: URL만 넣지 않았는지 확인한다. 위 예제처럼 메서드와 경로가 있는 요청 줄이 필요하다.
- `Request is missing a Host header`: 처음 직접 작성하는 요청에 `Host: example.com`처럼 대상 호스트를 넣는다.
- `Select a value to replace.`: 바꿀 값을 선택하고 `Add §`를 누른다.
- `Add payloads.`: `Payloads`에 바꿔 넣을 값을 한 줄에 하나씩 넣는다.

처음 직접 입력할 때 요청 줄을 `GET http://example.com/?q=demo HTTP/1.1`처럼 절대 URL로 썼다면 그 URL의 프로토콜과 호스트를 쓴다. 별도 연결 대상이 없는 이 경우 `Transport`는 비활성화되며, 바꾸려면 요청 URL의 `http://` 또는 `https://`를 수정하라는 안내가 나온다. History에서 가져온 요청은 원래 프로토콜을 유지한다. Replay에 별도 연결 대상이 있었다면 그 대상이 유지될 수 있으므로 상단 연결 대상을 확인한다.

## 사용 순서

1. 위처럼 요청을 직접 입력하거나, HTTP History나 HTTP Replay에서 요청을 골라 `Send to Fuzzer`를 누른다. 다른 요청을 가져와도 준비한 payload 목록은 남는다.
2. 요청에서 값을 선택하고 `Add §`를 누른다. query/form 값이 있으면 요청 위에 나타나는 `Choose a value`를 펼치고 `Value`에서 값을 골라 `Mark value`를 눌러도 된다. 표시한 값은 `§값§`이 되고, 원래 값은 표시 안에 남는다. 직접 `§값§`이나 `$payload$`(원래 값 없음)를 써도 된다. 이름이 같은 파라미터는 따로 표시되고, 인코딩은 바뀌지 않는다. `Undo`는 마지막 표시 작업을 되돌린다. 표시한 뒤 요청을 고쳤다면 되돌리지 않는다.
3. Payload를 한 줄에 하나씩 붙여 넣는다. `Import file`로 UTF-8 텍스트 파일을 가져오거나, Payloads의 `Generate payloads`를 펼쳐 작은 경계값 preset이나 정수 범위를 쓸 수 있다. 기본으로는 기존 목록에 더한다. `On import`에서 `Replace list`를 고르면 기존 목록을 바꾼다.
4. `Attack`에서 방식을 고른다. Sniper(기본)는 위치를 하나씩 골라 payload를 넣고, 나머지 위치에는 원래 값을 둔다. 요청 수는 payload 수 × 위치 수다. Battering ram은 모든 위치에 같은 payload를 넣는다. URL(경로와 쿼리)에 들어가는 payload는 기본으로 URL 인코딩한다. `Options`의 `URL-encode in the URL`을 끄면 그대로 넣는다. 본문과 헤더에는 그대로 넣는다. 같은 `Options`의 `Concurrent requests`는 동시에 보내는 요청 수다(1–16). 상단에서 실제 연결 대상, HTTP 버전, 위치 수, `N payloads → N planned requests`를 확인한다.
5. `Preview & details`에서 샘플을 최대 3개 본다. Content-Length는 본문 길이에 맞춰 다시 계산한다. 샘플은 템플릿을 확장한 미리보기다. 실제 전송 내용은 Match/Replace 등으로 달라질 수 있다. 큰 샘플은 생략하거나, 잘렸다는 안내를 보여 준다.
6. 대상이 본인 소유이거나 테스트 허가를 받았는지 확인하고 `Start`를 누른다. 공격은 백그라운드로 돌고, 결과는 도착하는 대로 보인다. `Stop`을 누르면 멈춘다. 보낼 수 없는 요청(잘못된 경로 등)은 그 결과 행에 이유를 남기고, 나머지는 계속 보낸다. 보낸 요청은 HTTP 기록에 `Sent from Fuzzer.` 메모와 함께 남는다.
7. 결과를 상태 코드 그룹, 크기(응답 본문 bytes), 소요 시간으로 거르고 정렬한다. 결과를 골라 요청과 응답을 본다. 두 결과를 비교하려면 한쪽에서 `Set compare base`를, 다른 쪽에서 `Compare selected`를 누른다. 기존 비교 화면이 열린다.

## 빈 값과 파일

- 공백을 지우지 않는다. `$&`, `$1`, `$payload$` 같은 문자열도 글자 그대로 쓴다.
- 빈 줄은 빈 payload다. 마지막 줄바꿈 하나는 구분자로만 본다. 빈 payload 하나만 넣으려면 빈 줄 하나를 입력한다.
- 파일의 CRLF와 CR은 붙여 넣을 때처럼 줄바꿈으로 처리한다. UTF-8 BOM은 문자로 남긴다. 잘못된 UTF-8은 변환하지 않고 거절한다.
- 파일을 읽는 사이 요청, 목록, 세션이 바뀌면 그 읽기 결과는 적용하지 않는다.
- 본문 값 선택은 완전한 UTF-8 본문에서만 돕는다. Base64, 바이너리, 잘린 본문을 일반 form 값처럼 바꾸지 않는다. Base64 본문에 marker를 직접 넣는 일부 API 기능은 이 화면에서 쓸 수 없다.

## 저장된 실행 다시 보기

`View or reuse a saved run`에서 `Refresh`를 누르고 실행을 고른다.

- `View results`: 현재 요청, payload, 연결 대상을 그대로 두고 저장된 결과만 본다.
- `Reuse setup`: 확인을 받은 뒤 요청과 payload 초안, 공격 방식, URL 인코딩, 동시 요청 수를 바꾼다. 저장된 실행에는 원래 원문 포맷, source transaction, target override가 없어 복구하지 않는다. 현재 초안에 있던 무관한 source와 target도 지운다. HTTP 버전은 저장된 template 버전이 있으면 그 값을, 없으면 HTTP/1.1을 쓴다. 실행 전에 대상과 버전을 다시 확인한다.
- 중단된 Sniper 실행을 `Reuse setup`하면 결과에 남은 payload만 원래 순서대로 되살린다. 빠진 payload는 만들지 않고, 몇 개가 남았는지 확인 창에 보여 준다. 위치 정보가 맞지 않으면 재사용하지 않는다. `View results`는 그대로 쓸 수 있다.
- 줄바꿈이 든 API payload나 편집기 한도를 넘는 실행은 초안으로 복원하지 않는다. `View results`로는 볼 수 있다.

## 연결이나 실행이 중단되었을 때

- 결과 조회가 잠시 실패해도 실행은 계속된다. 조회만 다시 하고 요청은 다시 보내지 않는다. 실행이 없어졌으면 마지막 결과를 남기고 `unavailable`로 표시한다.
- 결과는 750ms마다 모아 저장한다. 비정상 종료 직전의 결과는 잃을 수 있다.
- 다시 시작하면 마지막으로 저장한 결과까지를 중단된 실행으로 복구한다. 요청을 자동으로 다시 보내지 않는다.

## 한도

- Payload 최대 5,000개, 각 64 KiB, 바이트 합계 4 MiB
- Payload 편집기 텍스트와 가져올 파일은 각각 4 MiB 이하. 편집기 한도는 줄 구분자까지 세므로 바이트 합계 한도와 다르다.
- 요청 편집기 텍스트 2 MiB, 위치 최대 128개, payload별 확장 요청 4 MiB
- 시작 전 크기 추정은 공격 모드를 따르고, URL 인코딩한 경로 payload는 3배로 센다.
- 요청별 4 MiB 한도는 Host·Content-Length를 정리한 뒤의 요청에 적용한다. 넘는 요청은 보내지 않고 `Not sent`로 남는다.
- 공격 하나는 요청을 최대 50,000개 보낸다.
- 계획한 요청 수가 전송에 성공한 수는 아니다. 보낼 수 없는 요청은 그 행에 이유가 남는다.
