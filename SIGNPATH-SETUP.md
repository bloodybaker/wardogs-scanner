# SignPath Foundation setup

Repository: https://github.com/bloodybaker/wardogs-scanner
Owner: https://github.com/bloodybaker

## Completed preparation

- MIT original code and owner-authorized logo.
- e-Ukraine CC BY 4.0 attribution; exact match with the official download.
- Dependency/runtime license texts and notices in the release ZIP.
- GitHub-hosted build and offline fixtures; separate manual signing workflow.
- Embedded privacy policy and named roles in CODE_SIGNING.md.

## Application

Submit through https://signpath.org/apply.html with SIGNPATH-APPLICATION.md.
Acceptance and signing are not yet granted. Disclose security-state/device
diagnostics, required opt-in transfer, absence of an offline user mode and
CC BY 4.0 non-code assets for Foundation review. MFA is required for both
GitHub and the future SignPath account. Only claim account security verified
when the owner confirms it.

## Після прийняття

1. У SignPath підключити GitHub.com Trusted Build System та офіційний GitHub
   App. Обмежити походження вашим репозиторієм, main і workflow sign.yml.
2. Імпортувати `.signpath/artifact-configuration.xml`. Перевірити конфігурацію
   в SignPath на sample ZIP/EXE з GitHub CI. `version` = ProductVersion EXE.
3. Production policy має вимагати ручного підтвердження кожного запиту
   призначеним approver. GitHub environment approval цього не замінює.
4. Створити GitHub environment `signpath-production`, дозволити лише main,
   призначити reviewers. Secret `SIGNPATH_API_TOKEN`: лише submitter token.
   Приватний ключ залишається в SignPath. Додати environment variables:

| Variable | Значення |
| --- | --- |
| SIGNPATH_ORGANIZATION_ID | ID організації |
| SIGNPATH_PROJECT_SLUG | slug проєкту |
| SIGNPATH_SIGNING_POLICY_SLUG | production policy з ручним approval |
| SIGNPATH_ARTIFACT_CONFIGURATION_SLUG | slug імпортованої конфігурації |
| SIGNPATH_CERTIFICATE_THUMBPRINT | 40 hex SHA-1 thumbprint виданого сертифіката |

5. Запустити Sign scanner на main. GitHub-hosted runner виконає fixtures,
   збере код цього commit, завантажить EXE як artifact, чекатиме approval,
   перевірить підпис/час/сертифікат/метадані та обчислить фінальний SHA-256.
   Автоматичного release чи деплою немає.
6. Після схвалення додати attribution із CODE_SIGNING.md на домашню сторінку,
   `/scanner` та release page з посиланнями на код і policy.

## Випуск

Перед публічним релізом підняти версію в csproj і MainWindow.xaml.cs; наявну
0.7.4 не перезаписувати. Використати саме перевірений signed artifact за новою
immutable URL. Синхронно оновити backend SHA-256, розмір, версію й download URL.
Хеш до підписання не підходить. Перевірити підпис і хеш завантаженого публічного
EXE. Деплой окремий; локальна підготовка не змінює production або dist.

```powershell
dotnet run --project tests/Wardogs.Scanner.Smoke -c Release -- --fixtures
.\build.ps1 -OutputDirectory "$PWD/artifacts/local" -LockedRestore
```

Офіційні джерела: https://signpath.org/terms.html,
https://docs.signpath.io/trusted-build-systems/github,
https://docs.signpath.io/artifact-configuration/syntax.
