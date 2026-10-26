# Vulnerability Tracker v0.4

Windows용 로컬 GUI 취약점 제보 관리 도구입니다. GitHub Security Advisory와 버그바운티 제보를 같은 목록에서 관리합니다.

## 주요 기능
- GitHub Repository Security Advisory 동기화
- 버그바운티 / 직접 제보 수동 등록 및 상태 관리
- 제보 출처, 플랫폼, 프로그램, 제보 번호, 대상 기록
- 수동 등록한 제보의 제목 / 상태 / Severity / CVE / URL 등 상세 정보 수정
- 현재 GitHub 사용자가 author / collaborator / credited user인 advisory만 수집
- GitHub `local`, `triage`, `draft`, `published`, `closed` 상태 추적
- 버그바운티 `local`, `submitted`, `triage`, `accepted`, `published`, `duplicate`, `informative`, `not_applicable`, `resolved`, `closed` 상태 추적
- CVE 발급 감지 및 변경 이력 기록
- Severity / GitHub `updated_at` 변경 이력 기록
- GitHub repository URL 또는 advisory URL 붙여넣기로 저장소 자동 등록
- 출처 / 상태 필터와 대상 / 플랫폼 / 프로그램 / 제보 번호 / 제목 / GHSA / CVE / 벤더 답변 검색
- 개인 메모 및 벤더 답변 기록
- 최근 변경 강조 표시
- CSV / Excel(.xlsx) 내보내기
- Excel에 `Vulnerability Reports` + `Change History` 시트 생성
- SQLite 로컬 DB
- GitHub OAuth Device Flow 로그인
- OAuth access token은 Windows 자격 증명 저장소(keyring)에 저장

## 버그바운티 제보 등록
1. 대시보드의 **+ 버그바운티**를 클릭합니다. **+ 제보 등록** 또는 제보 목록의 **+ 추가**에서도 출처를 선택할 수 있습니다.
2. 출처에서 **버그바운티**를 선택합니다. 기존 GitHub 제보는 **GitHub (수동)**으로 등록할 수 있습니다.
3. **대상**과 **제목**을 입력합니다. 대상에는 도메인, 서비스, 제품 등 점검한 대상을 기록합니다.
4. 플랫폼, 프로그램, 제보 번호, 상태, Severity, CVE, 제보 URL, 메모를 필요한 만큼 입력하고 저장합니다.

플랫폼은 `HackerOne`, `Bugcrowd`, `Intigriti`, `YesWeHack`, `직접 제보`, `기타` 중 선택하거나 직접 입력할 수 있습니다. 프로그램은 참여한 프로그램 또는 벤더 이름이며, 제보 번호에는 해당 플랫폼의 report ID나 내부 관리 번호를 기록합니다.

등록한 항목을 선택한 뒤 **정보 수정**으로 상태와 제보 정보를 갱신할 수 있습니다. GitHub에서 동기화한 항목의 핵심 정보는 GitHub 동기화로 관리하며, 개인 메모와 벤더 답변을 앱에서 저장할 수 있습니다.

제보 목록에서 `Ctrl+F`로 검색창에 바로 이동하고, 출처를 고르면 해당 출처의 상태만 필터에 표시됩니다. 대시보드의 최근 항목을 두 번 클릭하면 상세 화면으로 이동합니다. 상세 화면의 메모와 벤더 답변은 입력을 멈춘 뒤 자동 저장되며, 항목을 바꾸거나 앱을 닫을 때도 저장합니다. `Ctrl+S` 또는 **지금 저장**으로 즉시 저장할 수 있습니다.

버그바운티에서 `accepted`는 프로그램이 제보를 인정한 상태, `published`는 제보 내용을 공개한 상태로 구분합니다. 공개 여부를 기록하려면 `published`를 선택하세요. 대시보드의 **Published**와 상태 필터는 GitHub와 버그바운티에 동일한 `published` 기준을 적용하며, `accepted`는 Published 건수에 포함하지 않습니다. 기존에 `accepted`로 저장한 제보는 자동 변경되지 않으므로 공개된 건만 **정보 수정**에서 `published`로 갱신할 수 있습니다.

버그바운티 플랫폼 API 자동 동기화는 지원하지 않습니다. 버그바운티 제보 정보와 벤더 답변은 직접 입력하며 GitHub 로그인이 필요하지 않습니다. 버그바운티 대상은 GitHub 동기화 저장소 목록에 추가되지 않습니다.

CSV와 Excel 내보내기에는 출처와 플랫폼 / 프로그램 / 제보 번호가 포함됩니다.
검색 / 출처 / 상태 필터를 적용하면 해당 목록만 내보냅니다. Excel 변경 이력도 같은 항목만 포함합니다.

## GitHub OAuth 연결 — 최초 1회
이 프로그램은 데스크톱 앱에서 Client Secret을 보관하지 않기 위해 GitHub OAuth Device Flow를 사용합니다.

1. GitHub → Settings → Developer settings → OAuth Apps → **New OAuth App**
2. 예시 입력
   - Application name: `GitHub Vulnerability Tracker`
   - Homepage URL: `http://127.0.0.1`
   - Authorization callback URL: `http://127.0.0.1`
3. OAuth App 생성 후 설정에서 **Enable Device Flow** 활성화
4. 발급된 **Client ID**를 VulnTracker → `GitHub 설정`에 입력
5. **GitHub 로그인** 클릭
6. 브라우저가 열리면 앱에 표시된 코드를 붙여넣고 승인
7. 연결 완료 후 저장소를 등록하고 **연결 테스트 / 동기화** 실행

### OAuth 권한 주의
미공개 Repository Security Advisory를 읽기 위해 앱은 OAuth `repo` scope를 요청합니다.
GitHub 공식 REST 문서상 OAuth app token으로 unpublished repository security advisory를 조회하려면 `repo` 또는 지원되는 repository-advisory read scope가 필요합니다. 일반 OAuth App scope 목록에서 `repo`는 저장소 전반에 넓은 권한을 가지므로 **본인이 만든 개인용 OAuth App만 사용**하세요.

토큰은 tracker.db에 저장하지 않고 Windows Credential Manager 계열 keyring backend에 저장합니다.

## 토큰 만료
GitHub OAuth App에서 만료되는 access token을 사용하는 경우 토큰이 만료될 수 있습니다. 현재 v0.4는 토큰 자동 갱신을 구현하지 않았으므로, 만료 시 **GitHub 로그인**을 다시 실행하면 됩니다. GitHub에서 토큰이나 앱의 접근 권한을 취소한 경우에도 다시 로그인해야 합니다. [GitHub 공식 OAuth 문서](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#expiring-access-tokens)

## 저장소 추가
아래 형식 모두 지원합니다.
- `keepassxreboot/keepassxc`
- `https://github.com/keepassxreboot/keepassxc`
- `https://github.com/keepassxreboot/keepassxc/security/advisories/GHSA-xxxx-xxxx-xxxx`

## 중요: 벤더 댓글 자동 수집 제한
GitHub의 Repository Security Advisory 웹 UI에서는 reporter/maintainer가 댓글로 대화할 수 있지만,
현재 공식 Repository Security Advisory REST API 문서에는 advisory 댓글을 읽는 endpoint가 제공되지 않습니다.
따라서 상태/CVE/updated_at은 자동 동기화하고, 실제 벤더 답변 전문은 앱의 `벤더 답변` 필드에 붙여넣어 관리합니다.

## 실행
```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\run.ps1

첫 실행에서는 Python 가상 환경과 의존성을 설치합니다. 이후에는 `requirements.txt`가 바뀌거나 환경이 손상된 경우에만 다시 설치합니다.
```

## EXE 빌드
기존 `VulnTracker.exe`가 실행 중이면 먼저 종료합니다.

```powershell
.\build_exe.ps1
```
결과: `dist\VulnTracker\VulnTracker.exe`

빌드 산출물은 GitHub 소스 저장소에 포함하지 않습니다. 위 명령으로 실행 파일을 생성할 수 있습니다.

## 데이터 위치
`%APPDATA%\GitHubVulnTracker\tracker.db`

기존 v0.1/v0.2/v0.3 DB가 있으면 필요한 컬럼과 변경 이력 테이블을 자동으로 추가합니다. 기존 제보, 메모, 벤더 답변, 변경 이력, GitHub 저장소와 설정은 같은 DB를 계속 사용합니다. 버그바운티 등록을 위해 DB를 삭제하거나 새로 만들 필요가 없습니다.

앱 표시 이름은 `Vulnerability Tracker`로 바뀌어도 데이터 폴더 이름 `GitHubVulnTracker`, Windows keyring의 서비스 이름, 기존 UI / OAuth 설정의 저장 위치는 유지됩니다. 같은 Windows 사용자 계정에서 업데이트하면 기존 로그인과 설정을 계속 사용할 수 있습니다.

## 기존 데이터가 있는 상태에서 업데이트
1. 실행 중인 앱을 종료합니다.
2. `%APPDATA%\GitHubVulnTracker` 폴더를 별도 위치에 복사해 백업합니다. `tracker.db-wal` 또는 `tracker.db-shm` 파일이 있으면 함께 보관합니다.
3. 새 버전의 프로그램 폴더로 실행 파일을 교체하거나 위 명령으로 다시 빌드합니다.
4. 같은 Windows 사용자로 새 앱을 실행합니다. 첫 실행에서 기존 DB에 새 필드를 추가합니다.

DB 백업에는 Windows 자격 증명 저장소에 저장된 GitHub 토큰과 Windows에 저장된 UI / OAuth 설정이 포함되지 않습니다. 프로그램 업데이트 시 이 저장소를 삭제하거나 초기화하지 마세요.
