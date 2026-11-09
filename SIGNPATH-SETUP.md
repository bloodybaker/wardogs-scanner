# SignPath Foundation: РїС–РґРіРѕС‚РѕРІРєР°

РЎС‚Р°РЅ РЅР° 2026-11-09: РїС–РґРіРѕС‚РѕРІР»РµРЅРѕ Р»РѕРєР°Р»СЊРЅРѕ. РџСѓР±Р»С–С‡РЅРѕРіРѕ СЂРµРїРѕР·РёС‚РѕСЂС–СЋ, РїСЂРёР№РЅСЏС‚С‚СЏ
Foundation, С‚РѕРєРµРЅР° С‚Р° СЃРµСЂС‚РёС„С–РєР°С‚Р° С‰Рµ РЅРµРјР°С”. MIT РґР»СЏ РІР»Р°СЃРЅРѕРіРѕ РєРѕРґСѓ РїРѕРіРѕРґР¶РµРЅРѕ.

## РџРµСЂРµРґ РїСѓР±Р»С–РєР°С†С–С”СЋ

1. Р—Р°РІРµСЂС€РёС‚Рё THIRD_PARTY_NOTICES.md: РїС–РґС‚РІРµСЂРґРёС‚Рё РїСЂР°РІР° РЅР° e-Ukraine С€СЂРёС„С‚Рё Р№
   Р»РѕРіРѕС‚РёРї Р°Р±Рѕ Р·Р°РјС–РЅРёС‚Рё С—С…; РІРєР»СЋС‡РёС‚Рё upstream Р»С–С†РµРЅР·С–С— Р· С‚РѕС‡РЅРёС… NuGet/runtime
   РїР°РєРµС‚С–РІ РґРѕ РґРёСЃС‚СЂРёР±СѓС‚РёРІР°. MIT РЅРµ Р·РјС–РЅСЋС” РїСЂР°РІР° С‚СЂРµС‚С–С… РѕСЃС–Р±.
2. РЎС‚РІРѕСЂРёС‚Рё РїРѕСЂРѕР¶РЅС–Р№ public GitHub repository `wardogs-scanner` Р±РµР· README.
3. РџС–СЃР»СЏ РїРµСЂРµРІС–СЂРєРё РїСЂР°РІ С‚Р° С„Р°Р№Р»С–РІ РІРёРєРѕРЅР°С‚Рё Р· D:\wdpbscanner:

```powershell
git init -b main
git add .github .signpath scripts src tests .gitignore global.json build.ps1 sign.ps1 README.md OFFLINE-SCAN.md LICENSE PRIVACY.md CODE_SIGNING.md SIGNPATH-SETUP.md SIGNPATH-APPLICATION.md THIRD_PARTY_NOTICES.md
git diff --cached --stat
git diff --cached
# РџРµСЂРµРІС–СЂРёС‚Рё: РЅРµРјР°С” Р·РІС–С‚С–РІ, РєР»СЋС‡С–РІ, work, backups, dist, .dotnet-home.
git commit -m "Prepare scanner for open-source code signing"
git remote add origin https://github.com/bloodybaker/wardogs-scanner.git
git push -u origin main
```

4. Р—Р°РїРѕРІРЅРёС‚Рё СЃРїСЂР°РІР¶РЅС– GitHub-РїРѕСЃРёР»Р°РЅРЅСЏ РЅР° Р°РІС‚РѕСЂС–РІ, reviewers С‚Р° approvers Сѓ
   CODE_SIGNING.md. РЈРІС–РјРєРЅСѓС‚Рё MFA, Р·Р°С…РёСЃС‚ main, review С– required Build scanner.
5. РџРµСЂРµРІС–СЂРёС‚Рё GitHub CI С‚Р° РѕРїСѓР±Р»С–РєСѓРІР°С‚Рё РѕРїРёСЃР°РЅРёР№ unsigned release СЏРє РґРѕРєР°Р·
   С–СЃРЅСѓСЋС‡РѕРіРѕ СЂРµР»С–Р·Сѓ. РќРµ РЅР°Р·РёРІР°С‚Рё Р№РѕРіРѕ РїС–РґРїРёСЃР°РЅРёРј.
6. РџРѕРґР°С‚Рё SIGNPATH-APPLICATION.md С‡РµСЂРµР· https://signpath.org/apply.html.
   Р—Р°СЏРІРєР° Р°РІС‚РѕРјР°С‚РёС‡РЅРѕ РЅРµ РЅР°РґСЃРёР»Р°С”С‚СЊСЃСЏ. Foundation РѕС†С–РЅСЋС” СЂРµРїСѓС‚Р°С†С–СЋ С‚Р° СѓРјРѕРІРё.
   РџСЂСЏРјРѕ СѓР·РіРѕРґРёС‚Рё Windows security/device diagnostics С– Р·РіРѕРґСѓ РЅР° РїРµСЂРµРґР°С‡Сѓ:
   РЅР°СЂР°Р·С– РЅРµРјР°С” РєРѕСЂРёСЃС‚СѓРІР°С†СЊРєРѕРіРѕ offline scan; РІС–РґРјРѕРІР° Р·СѓРїРёРЅСЏС” РІРµСЃСЊ scan.

## РџС–СЃР»СЏ РїСЂРёР№РЅСЏС‚С‚СЏ

1. РЈ SignPath РїС–РґРєР»СЋС‡РёС‚Рё GitHub.com Trusted Build System С‚Р° РѕС„С–С†С–Р№РЅРёР№ GitHub
   App. РћР±РјРµР¶РёС‚Рё РїРѕС…РѕРґР¶РµРЅРЅСЏ РІР°С€РёРј СЂРµРїРѕР·РёС‚РѕСЂС–С”Рј, main С– workflow sign.yml.
2. Р†РјРїРѕСЂС‚СѓРІР°С‚Рё `.signpath/artifact-configuration.xml`. РџРµСЂРµРІС–СЂРёС‚Рё РєРѕРЅС„С–РіСѓСЂР°С†С–СЋ
   РІ SignPath РЅР° sample ZIP/EXE Р· GitHub CI. `version` = ProductVersion EXE.
3. Production policy РјР°С” РІРёРјР°РіР°С‚Рё СЂСѓС‡РЅРѕРіРѕ РїС–РґС‚РІРµСЂРґР¶РµРЅРЅСЏ РєРѕР¶РЅРѕРіРѕ Р·Р°РїРёС‚Сѓ
   РїСЂРёР·РЅР°С‡РµРЅРёРј approver. GitHub environment approval С†СЊРѕРіРѕ РЅРµ Р·Р°РјС–РЅСЋС”.
4. РЎС‚РІРѕСЂРёС‚Рё GitHub environment `signpath-production`, РґРѕР·РІРѕР»РёС‚Рё Р»РёС€Рµ main,
   РїСЂРёР·РЅР°С‡РёС‚Рё reviewers. Secret `SIGNPATH_API_TOKEN`: Р»РёС€Рµ submitter token.
   РџСЂРёРІР°С‚РЅРёР№ РєР»СЋС‡ Р·Р°Р»РёС€Р°С”С‚СЊСЃСЏ РІ SignPath. Р”РѕРґР°С‚Рё environment variables:

| Variable | Р—РЅР°С‡РµРЅРЅСЏ |
| --- | --- |
| SIGNPATH_ORGANIZATION_ID | ID РѕСЂРіР°РЅС–Р·Р°С†С–С— |
| SIGNPATH_PROJECT_SLUG | slug РїСЂРѕС”РєС‚Сѓ |
| SIGNPATH_SIGNING_POLICY_SLUG | production policy Р· СЂСѓС‡РЅРёРј approval |
| SIGNPATH_ARTIFACT_CONFIGURATION_SLUG | slug С–РјРїРѕСЂС‚РѕРІР°РЅРѕС— РєРѕРЅС„С–РіСѓСЂР°С†С–С— |
| SIGNPATH_CERTIFICATE_THUMBPRINT | 40 hex SHA-1 thumbprint РІРёРґР°РЅРѕРіРѕ СЃРµСЂС‚РёС„С–РєР°С‚Р° |

5. Р—Р°РїСѓСЃС‚РёС‚Рё Sign scanner РЅР° main. GitHub-hosted runner РІРёРєРѕРЅР°С” fixtures,
   Р·Р±РµСЂРµ РєРѕРґ С†СЊРѕРіРѕ commit, Р·Р°РІР°РЅС‚Р°Р¶РёС‚СЊ EXE СЏРє artifact, С‡РµРєР°С‚РёРјРµ approval,
   РїРµСЂРµРІС–СЂРёС‚СЊ РїС–РґРїРёСЃ/С‡Р°СЃ/СЃРµСЂС‚РёС„С–РєР°С‚/РјРµС‚Р°РґР°РЅС– С‚Р° РѕР±С‡РёСЃР»РёС‚СЊ С„С–РЅР°Р»СЊРЅРёР№ SHA-256.
   РђРІС‚РѕРјР°С‚РёС‡РЅРѕРіРѕ release С‡Рё РґРµРїР»РѕСЋ РЅРµРјР°С”.
6. РџС–СЃР»СЏ СЃС…РІР°Р»РµРЅРЅСЏ РґРѕРґР°С‚Рё attribution С–Р· CODE_SIGNING.md РЅР° РґРѕРјР°С€РЅСЋ СЃС‚РѕСЂС–РЅРєСѓ,
   `/scanner` С‚Р° release page Р· РїРѕСЃРёР»Р°РЅРЅСЏРјРё РЅР° РєРѕРґ С– policy.

## Р’РёРїСѓСЃРє

РџРµСЂРµРґ РїСѓР±Р»С–С‡РЅРёРј СЂРµР»С–Р·РѕРј РїС–РґРЅСЏС‚Рё РІРµСЂСЃС–СЋ РІ csproj С– MainWindow.xaml.cs; РЅР°СЏРІРЅСѓ
0.7.4 РЅРµ РїРµСЂРµР·Р°РїРёСЃСѓРІР°С‚Рё. Р’РёРєРѕСЂРёСЃС‚Р°С‚Рё СЃР°РјРµ РїРµСЂРµРІС–СЂРµРЅРёР№ signed artifact Р·Р° РЅРѕРІРѕСЋ
immutable URL. РЎРёРЅС…СЂРѕРЅРЅРѕ РѕРЅРѕРІРёС‚Рё backend SHA-256, СЂРѕР·РјС–СЂ, РІРµСЂСЃС–СЋ Р№ download URL.
РҐРµС€ РґРѕ РїС–РґРїРёСЃР°РЅРЅСЏ РЅРµ РїС–РґС…РѕРґРёС‚СЊ. РџРµСЂРµРІС–СЂРёС‚Рё РїС–РґРїРёСЃ С– С…РµС€ Р·Р°РІР°РЅС‚Р°Р¶РµРЅРѕРіРѕ РїСѓР±Р»С–С‡РЅРѕРіРѕ
EXE. Р”РµРїР»РѕР№ РѕРєСЂРµРјРёР№; Р»РѕРєР°Р»СЊРЅР° РїС–РґРіРѕС‚РѕРІРєР° РЅРµ Р·РјС–РЅСЋС” production Р°Р±Рѕ dist.

```powershell
dotnet run --project tests/Wardogs.Scanner.Smoke -c Release -- --fixtures
.\build.ps1 -OutputDirectory "$PWD/artifacts/local" -LockedRestore
```

РћС„С–С†С–Р№РЅС– РґР¶РµСЂРµР»Р°: https://signpath.org/terms.html,
https://docs.signpath.io/trusted-build-systems/github,
https://docs.signpath.io/artifact-configuration/syntax.
