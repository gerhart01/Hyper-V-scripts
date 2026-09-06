# Spider Stone

[English](README.md) · **Русский**

Инструмент для анализа **Windows Optional Features** и их компонентов: по имени фичи
восстанавливает полную цепочку «фича → пакеты → компоненты → файлы» из данных
Component-Based Servicing (CBS), распаковывает манифесты WinSxS через `wcp.dll`
и выгружает подробную карту компонента (файлы с хэшами, зависимости, реестр,
категории и т.д.) в CSV и читаемый HTML-отчёт.

Работает **полностью локально** — ничего не выгружает в сеть.

---

## Состав

| Файл | Назначение |
|---|---|
| `Spider-Stone.ps1` | Основной скрипт: поиск по реестру CBS, сбор манифестов, парсинг, экспорт |
| `WCPExtractor.psm1` | Модуль распаковки WCP-сжатых файлов (декомпрессия манифестов через `wcp.dll`) |

Оба файла должны лежать в одной папке.

---

## Требования

- **PowerShell 7.0+**
- Windows 10/11 или Windows Server (x64, x86 или ARM64)
- Права администратора (рекомендуются — для чтения разделов реестра CBS и файлов WinSxS)
- `wcp.dll` в системе (ищется автоматически; можно указать вручную)

---

## Принцип работы

```
FeatureName
   │  реестр: Component Based Servicing\{OptionalFeatures, UpdateDetect}
   ▼
Один быстрый проход по Packages (.NET RegistryKey API):
Пакеты (Packages\*\Updates)  ──► Owner-пакеты (Packages\*\Owners) ──► [MUM-файлы]
   │  имя пакета → префикс манифеста (arch_ + имя, обрезка суффиксов)
   ▼
Манифесты  C:\Windows\WinSxS\Manifests\<prefix>*.manifest   (WCP-сжатые)
   │  WCPExtractor: wcp.dll → декомпрессия в XML
   ▼
Парсинг <assembly>: файлы + полный «след» компонента
   ▼
Вывод: CSV (по видам данных) + HTML-отчёт + GridView
```

> **Производительность.** Поиск пакетов идёт через нативный .NET `Microsoft.Win32.RegistryKey`
> (а не через провайдер `Get-ChildItem`/`Get-ItemProperty`) за один проход по хиву. На системе
> с ~15 000 пакетов CBS полный анализ фичи `DiskIo-QoS` ускорился с **~570 с до ~5 с** (~110×).
> Память при этом остаётся минимальной (хранится лишь набор имён найденных пакетов), поэтому
> отдельного ключа для экономии памяти не потребовалось.

---

## Параметры `Spider-Stone.ps1`

| Параметр | Тип | Описание |
|---|---|---|
| `-FeatureName` | string | Имя Optional Feature для анализа. Без него — показывает список установленных фич. |
| `-OutputDirectory` | string | Каталог для результатов. По умолчанию `.\OptionalFeatureFiles`. |
| `-ParsingMum` | switch | Включить рекурсивный разбор MUM-файлов из `C:\Windows\servicing\Packages`. |
| `-NotShowGridView` | switch | Не открывать результаты в `Out-GridView`. |
| `-OpenReport` | switch | Открыть готовый HTML-отчёт в браузере по умолчанию по завершении. |
| `-ComponentFilter` | string | Выводить только компоненты, чьё наименование содержит это слово (без учёта регистра). Фильтрует все виды данных: файлы, зависимости, реестр, CSV, HTML, GridView. |
| `-PathToWcp` | string | Явный путь к `wcp.dll` для распаковки. |
| `-SearchWcpDll` | switch | Найти и показать актуальную `wcp.dll` под разрядность системы (через `Find-LatestWCPDll`). |
| `-VerboseOutput` | switch | Подробное логирование. |
| `-Help`, `-?` | switch | Показать встроенную справку. |

---

## Примеры

```powershell
# Список установленных Optional Features
.\Spider-Stone.ps1

# Анализ конкретной фичи
.\Spider-Stone.ps1 -FeatureName "Windows-Defender-Default-Definitions"

# С рекурсивным разбором MUM и подробным логом
.\Spider-Stone.ps1 -FeatureName "RSAT" -ParsingMum -VerboseOutput

# Только компоненты, чьё наименование содержит "Defender"
.\Spider-Stone.ps1 -FeatureName "Containers" -ComponentFilter "Defender"

# Свой каталог вывода, без GridView
.\Spider-Stone.ps1 -FeatureName "RSAT" -OutputDirectory "C:\Temp\RSAT" -NotShowGridView

# Указать конкретную wcp.dll
.\Spider-Stone.ps1 -FeatureName "RSAT" -PathToWcp "C:\Windows\System32\wcp.dll"

# Просто найти актуальную wcp.dll
.\Spider-Stone.ps1 -SearchWcpDll
```

---

## Выходные данные

Всё пишется в `<OutputDirectory>\<Feature>\`. Для каждого вида данных — свой CSV,
плюс сводный HTML-отчёт.

| Файл | Содержимое |
|---|---|
| `OptionalFeatureFiles_<Feature>.csv` | Файлы компонентов (обогащённые — см. ниже) |
| `Components_<Feature>.csv` | По одной строке на компонент: полный identity + DisplayName/Description + число файлов |
| `Dependencies_<Feature>.csv` | Рёбра зависимостей компонент → компонент (`dependentAssembly`) |
| `Registry_<Feature>.csv` | Реестровый след: ключи/значения, которые ставит компонент |
| `Categories_<Feature>.csv` | Членство в категориях/фичах (`categoryMembership`) |
| `Directories_<Feature>.csv` | Каталоги, создаваемые компонентом, + их SDDL |
| `Strings_<Feature>.csv` | Локализация (`stringTable`): displayName/description и пр. |
| `Providers_<Feature>.csv` | ETW-провайдеры компонента |
| `Tasks_<Feature>.csv` | Задачи планировщика, регистрируемые компонентом |
| `Extras_<Feature>.csv` | Маркеры: deployment / infFile / appxRegistration / serviceData / migration / protocolDriver |
| `Report_<Feature>.html` | Самодостаточный HTML-отчёт (карточки-сводка + сворачиваемые таблицы, тёмная/светлая тема) |

### Что извлекается по каждому файлу компонента

`FileName`, `DestinationPath`, `SourceName`, `ImportPath`, `SourcePath`, `WriteableType`,
`HashAlgorithm` + `HashValue` (SHA-хэш файла), `SecurityDescriptor` (SDDL-имя),
`LinkTarget` (хардлинки), плюс identity компонента (`Component`, `Version`,
`Architecture`, `PublicKeyToken`).

### HTML-отчёт

Формируется **автоматически** при анализе любой фичи — отдельный ключ не нужен,
достаточно указать `-FeatureName`. По завершении путь к файлу выводится в консоль
(строка `HTML report : ...`). Путь выводится как гиперссылка терминала (OSC 8), она
подсвечивается — **но Windows Terminal из соображений безопасности открывает по клику
только `http`/`https`, а не локальные `file://`**. Чтобы отчёт открывался автоматически,
запускайте с ключом **`-OpenReport`** (открывает браузер по умолчанию):

```powershell
.\Spider-Stone.ps1 -FeatureName "DiskIo-QoS" -OpenReport
```

Либо откройте путь вручную (`Invoke-Item <путь>`) — он всегда печатается в консоль.

Локальный файл `Report_<Feature>.html` — открывается в любом браузере, без интернета.
Сводка-карточки сверху, далее сворачиваемые секции по каждому виду данных
(sticky-заголовки таблиц, моноширинный шрифт для хэшей/ключей/GUID). Крупные таблицы
(реестр) обрезаются до 500 строк с пометкой — полные данные в соответствующем CSV.

```powershell
.\Spider-Stone.ps1 -FeatureName "DiskIo-QoS"
# -> .\OptionalFeatureFiles\DiskIo-QoS\Report_DiskIo-QoS.html
Invoke-Item .\OptionalFeatureFiles\DiskIo-QoS\Report_DiskIo-QoS.html   # открыть
```

### Прогресс выполнения

Все длинные этапы — поиск пакетов в реестре CBS, поиск owner-пакетов, копирование,
WCP-распаковка и разбор манифестов — показывают прогресс-бар (`Write-Progress`) с
номером текущего элемента и процентом, чтобы было видно, что скрипт работает, а не завис.

---

## Модуль `WCPExtractor.psm1`

Экспортируемые функции:

| Функция | Назначение |
|---|---|
| `Expand-WCPFile -InputFile <path> [-OutputFile <path>] [-WCPDllPath <path>]` | Распаковать WCP-сжатый файл (манифест) в XML. Несжатые файлы проходят «насквозь». |
| `Find-LatestWCPDll` | Найти актуальную `wcp.dll` под разрядность системы (System32 + WinSxS servicing stack). |
| `Test-WCPManifest [-ManifestName <name>] [-OutputPath <dir>]` | Проверочная распаковка манифеста из WinSxS + валидация XML. |
| `Test-WCPManifestCompressed -InputFile <path>` | Сжат ли манифест (нативный `IsManifestCompressed`). Возвращает `$null`, если экспорт отсутствует в данной сборке. |
| `Get-WCPCompressionTypeName -Code <n> [-Bytes <byte[]>]` | Читаемое имя типа сжатия по числовому коду `GetCompressedFileType`. |
| `Get-ProcessorArchitecture` | `x86` / `x64` / `arm64`. |

### Как устроена распаковка

`Expand-WCPFile` загружает `wcp.dll` в рантайме (источник истины — живая библиотека,
её версия может меняться) и дёргает нативные функции:
`GetCompressedFileType` → `InitializeDeltaCompressor` →
`LoadFirstResourceLanguageAgnostic` → `DeltaDecompressBuffer`.

**Типы WCP-сжатия** (заголовок `'D' 'C' <T> 0x01`):

| Сигнатура | Код | Обработка |
|---|---|---|
| `DCM\x01` | 4 | Delta-манифест — **распаковывается** (основной путь) |
| `DCS\x01` | 5 | LZMS-хранилище — детектируется, точка расширения (не распаковывается) |
| `DCD/DCN/DCH/DCX` | 1/2/3/6 | Детектируются, чёткая диагностика (не распаковываются) |
| нет заголовка | 0 | Не WCP-сжат — файл отдаётся как есть |

---

## Технические детали

**Разделы реестра CBS:**
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Notifications\OptionalFeatures`
- `HKLM\...\Component Based Servicing\UpdateDetect`
- `HKLM\...\Component Based Servicing\Packages` (подключи `Updates`, `Owners`)

**Пути:** манифесты — `C:\Windows\WinSxS\Manifests`; MUM — `C:\Windows\servicing\Packages`.

**Парсинг манифестов** устойчив к пространствам имён (asm.v1/v2/v3, xmldsig, ETW,
task-scheduler) — через XPath `local-name()`.

**Поддержка архитектур:** x64 (AMD64), x86 (i386), ARM64 — определяется автоматически,
подбирается соответствующая `wcp.dll`.

---

## Источники, благодарности и лицензия

**Онлайн-источник, положенный в основу разработки:**

- **wcpex** by Smx (Stefano Moioli) — <https://github.com/smx-smx/wcpex/> —
  референсная реализация распаковки WCP-сжатых манифестов через нативные вызовы
  `wcp.dll` (`GetCompressedFileType` → `DeltaDecompressBuffer`). Модуль
  `WCPExtractor.psm1` — порт этой техники на PowerShell; оригинальная лицензия
  (zlib-style) сохранена в шапке модуля.

**Прочее:**

- Формат заголовка WCP-сжатия (`'D' 'C' <T> 0x01`) и enum типов сверялись с
  декомпиляцией системных библиотек обслуживания (`ServicingCommon.dll`);
  публичного онлайн-описания у этих констант нет, поэтому `wcp.dll` грузится в
  рантайме как источник истины (её версия/enum могут меняться).
- Модель CBS / WinSxS / манифестов — стандартный механизм обслуживания Windows.
