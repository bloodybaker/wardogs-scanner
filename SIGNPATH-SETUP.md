# SignPath Foundation: підготовка

Current status: https://github.com/bloodybaker/wardogs-scanner has been created
as a private repository. Initial import is complete. The commands below are
historical setup instructions; do not repeat them. Make the repository public
after asset review, before applying. Foundation acceptance and signing remain pending.

## Перед публікацією

1. Завершити THIRD_PARTY_NOTICES.md: підтвердити права на e-Ukraine шрифти й
   логотип або замінити їх; включити upstream ліцензії з точних NuGet/runtime
   пакетів до дистрибутива. MIT не змінює права третіх осіб.
2. Створити порожній public GitHub repository `wardogs-scanner` без README.
3. Після перевірки прав та файлів виконати з D:\wdpbscanner:

```powershell
git init -b main
git add .github .signpath scripts src tests .gitignore global.json build.ps1 sign.ps1 README.md OFFLINE-SCAN.md LICENSE PRIVACY.md CODE_SIGNING.md SIGNPATH-SETUP.md SIGNPATH-APPLICATION.md THIRD_PARTY_NOTICES.md
git diff --cached --stat
git diff --cached
# Перевірити: немає звітів, ключів, work, backups, dist, .dotnet-home.
git commit -m "Prepare scanner for open-source code signing"
git remote add origin https://github.com/bloodybaker/wardogs-scanner.git
git push -u origin main
```

4. Заповнити справжні GitHub-посилання на авторів, reviewers та approvers у
   CODE_SIGNING.md. Увімкнути MFA, захист main, review і required Build scanner.
5. Перевірити GitHub CI та опублікувати описаний unsigned release як доказ
   існуючого релізу. Не називати його підписаним.
6. Подати SIGNPATH-APPLICATION.md через https://signpath.org/apply.html.
   Заявка автоматично не надсилається. Foundation оцінює репутацію та умови.
   Прямо узгодити Windows security/device diagnostics і згоду на передачу:
   наразі немає користувацького offline scan; відмова зупиняє весь scan.

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
