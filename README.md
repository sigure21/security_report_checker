# GitHub Vulnerability Tracker v0.3

Windows용 로컬 GUI 취약점 제보 관리 도구입니다.

## 주요 기능
- GitHub Repository Security Advisory 동기화
- 현재 GitHub 사용자가 author / collaborator / credited user인 advisory만 수집
- `triage`, `draft`, `published`, `closed` 상태 추적
- CVE 발급 감지 및 변경 이력 기록
- Severity / GitHub `updated_at` 변경 이력 기록
- GitHub repository URL 또는 advisory URL 붙여넣기로 저장소 자동 등록
- Repo / 제목 / GHSA / CVE / 벤더 답변 검색
- 개인 메모 및 벤더 답변 기록
- 최근 변경 강조 표시
- CSV / Excel(.xlsx) 내보내기
- Excel에 `Vulnerability Reports` + `Change History` 시트 생성
- SQLite 로컬 DB
- GitHub OAuth Device Flow 로그인
- OAuth access token은 Windows 자격 증명 저장소(keyring)에 저장

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
GitHub OAuth App에서 expiring user access token을 사용하는 경우 access token이 만료될 수 있습니다. 현재 v0.3은 자동 refresh를 위해 Client Secret을 저장하지 않으므로, 만료 시 **GitHub 로그인**을 다시 실행하면 됩니다.

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
```

## EXE 빌드
```powershell
.\build_exe.ps1
```
결과: `dist\VulnTracker\VulnTracker.exe`

## 데이터 위치
`%APPDATA%\GitHubVulnTracker\tracker.db`

기존 v0.1/v0.2 DB가 있으면 필요한 컬럼과 변경 이력 테이블을 자동으로 추가합니다.
