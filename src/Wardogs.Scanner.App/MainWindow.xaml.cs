using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;

namespace Wardogs.Scanner;

public partial class MainWindow : Window
{
    private const string ApiBase = "https://wardogs.com.ua";
    private const string Version = "0.7.7";
    private static readonly Regex IncidentPattern = new("^[0-9a-f]{32}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private readonly ApiClient _api = new();
    private bool _offline;
    private bool _busy;
    private OfflineReport? _pendingReport;
    private string? _savedPath;

    public MainWindow()
    {
        InitializeComponent();
        OneTimeCode.Focus();
        UpdateStartButtonState();
    }

    private void InputsChanged(object sender, RoutedEventArgs e) => UpdateStartButtonState();

    private void UpdateStartButtonState()
    {
        if (StartButton == null || OneTimeCode == null || ConsentProcesses == null || ConsentSystem == null || ConsentTransfer == null) return;
        StartButton.IsEnabled = !_busy
            && ConsentProcesses.IsChecked == true
            && ConsentSystem.IsChecked == true
            && ConsentTransfer.IsChecked == true
            && (_pendingReport != null || _offline || TryParseOneTimeCode(OneTimeCode.Text, out _, out _));
    }

    private void TitleBarMouseDown(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed) DragMove();
    }

    private void MinimizeClick(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void CloseClick(object sender, RoutedEventArgs e) => Close();

    private void PrivacyClick(object sender, RoutedEventArgs e)
    {
        using var stream = typeof(MainWindow).Assembly.GetManifestResourceStream("Wardogs.Scanner.Privacy");
        if (stream == null) throw new InvalidOperationException("Privacy resource is missing.");
        using var reader = new StreamReader(stream);
        var text = new System.Windows.Controls.TextBox {
            Text = reader.ReadToEnd(), IsReadOnly = true, TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = System.Windows.Controls.ScrollBarVisibility.Auto,
            Padding = new Thickness(20), FontSize = 14
        };
        new Window {
            Owner = this, Title = "Приватність WARDOGS Scanner", Width = 700, Height = 580,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, Content = text
        }.ShowDialog();
    }

    private void CodeKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && StartButton.IsEnabled) StartClick(StartButton, new RoutedEventArgs());
    }

    private async void StartClick(object sender, RoutedEventArgs e)
    {
        if (ConsentProcesses.IsChecked != true || ConsentSystem.IsChecked != true || ConsentTransfer.IsChecked != true)
        {
            SetStatus("Підтвердьте всі три пункти згоди.", "УВАГА", "#FFD060");
            return;
        }
        if (_pendingReport != null)
        {
            SetControlsEnabled(false);
            await SaveOfflineAsync(_pendingReport);
            return;
        }
        var validCode = TryParseOneTimeCode(OneTimeCode.Text, out var incidentId, out var challenge);
        if (!validCode) incidentId = "";
        if (!_offline && !validCode)
        {
            SetStatus("Вставте повний одноразовий код від адміністратора.", "КОД", "#FF7D7D");
            OneTimeCode.Focus();
            return;
        }

        SetControlsEnabled(false);
        var started = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000d;
        try
        {
            using var guard = new CancellationTokenSource(TimeSpan.FromMinutes(15));
            var buildHash = await BuildHashAsync();
            StartResponse? session = null;
            if (!_offline)
            {
                SetStatus("Перевіряємо одноразовий код…", "З'ЄДНАННЯ", "#FFD83D");
                Progress.Value = 15;
                try { session = await _api.StartAsync(ApiBase, incidentId, challenge, new(1, Version, buildHash), guard.Token); }
                catch (Exception ex) when (ApiClient.IsConnectionFailure(ex) && !guard.IsCancellationRequested)
                {
                    _offline = true;
                    UpdateMode();
                    SetStatus("Сайт недоступний. Збережемо результат у JSON після перевірки.", "ОФЛАЙН", "#FFD060");
                }
            }
            OneTimeCode.Clear();
            SetStatus("Аналізуємо процеси, Windows і браузерні збіги…", "СКАНУВАННЯ", "#FFD83D");
            Progress.Value = 35;
            var processTask = CollectionSafety.RunAsync(() => ProcessCollector.CollectAsync(guard.Token),
                ex => (Module: CollectionSafety.Failure("processes", started, ex), Evidence: new List<Evidence>()));
            var forensicTask = CollectionSafety.RunAsync(() => ForensicCollector.CollectAsync(guard.Token),
                ex => (Modules: new List<ModuleResult> { CollectionSafety.Failure("forensics", started, ex) }, Evidence: new List<Evidence>(), Errors: new List<string> { CollectionSafety.Reason(ex) }));
            var browserTask = CollectionSafety.RunAsync(() => BrowserHistoryCollector.CollectAsync(guard.Token),
                ex => (Module: CollectionSafety.Failure("browser_history", started, ex), Evidence: new List<Evidence>(), Errors: new List<string> { CollectionSafety.Reason(ex) }));
            var externalTask = CollectionSafety.RunAsync(() => ExternalAccessCollector.CollectAsync(guard.Token),
                ex => (Module: CollectionSafety.Failure("external_process_access", started, ex), Evidence: new List<Evidence>()));
            var macroTask = CollectionSafety.RunAsync(() => MacroCollector.CollectAsync(guard.Token),
                ex => (Module: CollectionSafety.Failure("macro_scripts", started, ex), Evidence: new List<Evidence>()));
            var contextTask = CollectionSafety.RunAsync(() => ProcessContextCollector.CollectAsync(guard.Token),
                ex => (Module: CollectionSafety.Failure("process_context", started, ex), Evidence: new List<Evidence>()));
            var stages = new (string Name, Task Task)[] {
                ("процеси", processTask), ("Windows і DLL", forensicTask),
                ("браузери", browserTask), ("доступ до гри", externalTask),
                ("макроси", macroTask), ("походження процесів", contextTask),
            };
            var collection = Task.WhenAll(stages.Select(stage => stage.Task));
            var elapsed = Stopwatch.StartNew();
            while (!collection.IsCompleted)
            {
                await Task.WhenAny(collection, Task.Delay(1000, guard.Token));
                guard.Token.ThrowIfCancellationRequested();
                var pending = stages.Where(stage => !stage.Task.IsCompleted).Select(stage => stage.Name).ToArray();
                var completed = stages.Length - pending.Length;
                var detail = $"{completed}/{stages.Length} · {elapsed.Elapsed:mm\\:ss} · " + string.Join(", ", pending);
                SetStatus(detail, "СКАНУВАННЯ", "#FFD83D");
                Status.ToolTip = detail;
                Progress.Value = 35 + 27d * completed / stages.Length;
            }
            await collection;
            var (processes, evidence) = await processTask;
            SetStatus("Перевіряємо захист, історію запусків і відомі cheat-домени…", "СКАНУВАННЯ", "#FFD83D");
            Progress.Value = 62;
            var forensic = await forensicTask;
            var browser = await browserTask;
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000d;
            var admin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            var system = new ModuleResult("system", "success", now, now, 1, "");
            var modules = new List<ModuleResult> { processes, system };
            modules.AddRange(forensic.Modules);
            modules.Add(browser.Module);
            var external = await externalTask; var macros = await macroTask;
            modules.Add(external.Module); modules.Add(macros.Module);
            evidence.AddRange(external.Evidence); evidence.AddRange(macros.Evidence);
            var context = await contextTask;
            modules.Add(context.Module); evidence.AddRange(context.Evidence);
            evidence.AddRange(forensic.Evidence);
            evidence.AddRange(browser.Evidence);
            var totalEvidence = evidence.Count;
            evidence = EvidencePrioritizer.Select(evidence);
            if (totalEvidence > evidence.Count)
                modules.Add(new ModuleResult("evidence_limit", "partial", now, now, totalEvidence,
                    $"У звіт включено {evidence.Count} із {totalEvidence} артефактів за пріоритетом. Частину записів пропущено через обмеження розміру."));
            var errors = forensic.Errors.Concat(browser.Errors)
                .Concat(modules.Where(m => m.Status != "success" && m.Error.Length > 0).Select(m => m.Name + ": " + m.Error))
                .Select(value => CollectionSafety.Limit(value)).Distinct().Take(100).ToList();
            DeviceIdentity? identity = null;
            try { identity = DeviceIdentityCollector.Collect(); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                modules.Add(CollectionSafety.Failure("device_identity", started, ex));
            }
            var report = new ScanReport(1, session?.SteamId ?? "", Version, buildHash, started, now, admin,
                new(true, ["processes", "system", "services_drivers", "persistence", "security_posture", "runtime_security", "dma_devices", "tamper_indicators", "loaded_modules", "persistence_hooks", "recent_executables", "historical_execution", "browser_history", "browser_matched_urls", "external_process_access", "macro_scripts", "process_context", "cleanup", "device_identity", "transfer"]),
                modules, evidence, errors, identity);
            var offlineReport = OfflineReport.Create(incidentId, report);
            if (session == null)
            {
                await SaveOfflineAsync(offlineReport);
                return;
            }
            SetStatus("Зашифровано передаємо звіт WARDOGS…", "НАДСИЛАННЯ", "#FFD83D");
            Progress.Value = 85;
            try
            {
                var accepted = await _api.SubmitAsync(ApiBase, session.IncidentId, session.UploadToken, report, guard.Token);
                Progress.Value = 100;
                StartButton.Content = "ПЕРЕВІРКУ ЗАВЕРШЕНО";
                SetStatus($"Звіт прийнято · {accepted.Status} · № {accepted.ReportId}", "ЗАВЕРШЕНО", "#55D68A");
            }
            catch (Exception ex)
            {
                await SaveOfflineAsync(offlineReport, "Не вдалося надіслати: " + ex.Message);
            }
        }
        catch (OperationCanceledException)
        {
            Progress.Value = 0;
            SetStatus("Час перевірки вичерпано. Якщо код уже використано, отримайте новий у адміністратора.", "ПЕРЕВІРКУ ЗУПИНЕНО", "#FFD060");
            SetControlsEnabled(true);
        }
        catch (Exception ex)
        {
            Progress.Value = 0;
            SetStatus("Перевірку не завершено: " + ex.Message, "ПОМИЛКА", "#FF7272");
            SetControlsEnabled(true);
        }
    }

    private void OfflineClick(object sender, RoutedEventArgs e)
    {
        _offline = !_offline;
        UpdateMode();
        UpdateStartButtonState();
        SetStatus(_offline ? "Готово до офлайн-перевірки · код не потрібен" : "Очікуємо одноразовий код", "РЕЖИМ", "#AAB5C4");
    }

    private void UpdateMode()
    {
        OfflineButton.Content = _offline ? "●  ОФЛАЙН · увімкнено" : "○  Перейти в офлайн";
        ModeDescription.Text = _offline ? "Без інтернету й коду · результат у JSON" : "Введіть код, отриманий від адміністратора";
        CodeLabel.Text = _offline ? "КОД ПЕРЕВІРКИ · НЕОБОВ’ЯЗКОВО" : "ОДНОРАЗОВИЙ КОД";
        ConnectionLabel.Text = _offline ? "Звіт зберігається на цьому ПК" : "Зашифроване з’єднання";
        AccessLabel.Text = _offline ? "Передача JSON адміністратору" : "Одноразовий доступ · 30 хвилин";
        ConsentTransfer.Content = _offline ? "Зберегти звіт у JSON для адміністратора" : "Надіслати звіт або зберегти JSON при збої";
    }

    private async Task SaveOfflineAsync(OfflineReport report, string reason = "")
    {
        _pendingReport = report;
        Exception? failure = null;
        foreach (var root in new[] { Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                     Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), Path.GetTempPath() }.Where(p => !string.IsNullOrWhiteSpace(p)))
        {
            try
            {
                _savedPath = await report.SaveAsync(Path.Combine(root, "WARDOGS", "Reports"));
                _pendingReport = null;
                Progress.Value = 100;
                SavedReportButton.Visibility = Visibility.Visible;
                SavedReportButton.ToolTip = _savedPath;
                StartButton.Content = "ПЕРЕВІРКУ ЗАВЕРШЕНО";
                SetStatus((reason.Length > 0 ? reason + "\n" : "") + "JSON збережено. Передайте файл адміністратору.\n" + _savedPath, "ЗБЕРЕЖЕНО", "#55D68A");
                ReportScroll.UpdateLayout();
                ReportScroll.ScrollToEnd();
                return;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException) { failure = ex; }
        }
        SetStatus("Не вдалося зберегти JSON: " + failure?.Message + "\nЗвільніть місце та натисніть «Зберегти JSON ще раз». Звіт залишається у відкритому сканері.", "ПОМИЛКА", "#FF7272");
        StartButton.Content = "ЗБЕРЕГТИ JSON ЩЕ РАЗ";
        SetControlsEnabled(true);
        ReportScroll.UpdateLayout();
        ReportScroll.ScrollToEnd();
    }

    private void OpenSavedReport(object sender, RoutedEventArgs e)
    {
        if (_savedPath == null) return;
        try { Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{_savedPath}\"") { UseShellExecute = true }); }
        catch (Exception ex) { SetStatus("Файл збережено: " + _savedPath + "\n" + ex.Message, "JSON", "#FFD060"); }
    }

    private static bool TryParseOneTimeCode(string value, out string incidentId, out string challenge)
    {
        incidentId = ""; challenge = "";
        var code = (value ?? "").Trim();
        var separator = code.IndexOf('.');
        if (separator <= 0 || separator == code.Length - 1 || code.IndexOf('.', separator + 1) >= 0) return false;
        incidentId = code[..separator].ToLowerInvariant();
        challenge = code[(separator + 1)..];
        return IncidentPattern.IsMatch(incidentId) && challenge.Length is >= 32 and <= 100 && challenge.All(ch => char.IsLetterOrDigit(ch) || ch is '-' or '_');
    }

    private void SetControlsEnabled(bool enabled)
    {
        _busy = !enabled;
        OneTimeCode.IsEnabled = enabled;
        OfflineButton.IsEnabled = enabled && _pendingReport == null;
        ConsentProcesses.IsEnabled = enabled; ConsentSystem.IsEnabled = enabled; ConsentTransfer.IsEnabled = enabled;
        UpdateStartButtonState();
    }

    private void SetStatus(string text, string badge, string color)
    {
        Status.Text = text;
        Status.ToolTip = text;
        var brush = (SolidColorBrush)new BrushConverter().ConvertFromString(color)!;
        Status.Foreground = brush;
    }

    private static async Task<string> BuildHashAsync()
    {
        var path = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName ?? Path.Combine(AppContext.BaseDirectory, "WardogsScanner.exe");
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream)).ToLowerInvariant();
    }
}
