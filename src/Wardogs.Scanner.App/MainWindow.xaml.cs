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
    private const string Version = "0.7.4";
    private static readonly Regex IncidentPattern = new("^[0-9a-f]{32}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private readonly ApiClient _api = new();

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
        StartButton.IsEnabled = OneTimeCode.IsEnabled
            && ConsentProcesses.IsChecked == true
            && ConsentSystem.IsChecked == true
            && ConsentTransfer.IsChecked == true
            && TryParseOneTimeCode(OneTimeCode.Text, out _, out _);
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
        if (!TryParseOneTimeCode(OneTimeCode.Text, out var incidentId, out var challenge))
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
            SetStatus("Перевіряємо одноразовий код…", "З'ЄДНАННЯ", "#FFD83D");
            Progress.Value = 15;
            var session = await _api.StartAsync(ApiBase, incidentId, challenge, new(1, Version, buildHash), guard.Token);
            OneTimeCode.Clear();
            SetStatus("Аналізуємо процеси, Windows і браузерні збіги…", "СКАНУВАННЯ", "#FFD83D");
            Progress.Value = 35;
            var processTask = ProcessCollector.CollectAsync(guard.Token);
            var forensicTask = ForensicCollector.CollectAsync(guard.Token);
            var browserTask = BrowserHistoryCollector.CollectAsync(guard.Token);
            var externalTask = ExternalAccessCollector.CollectAsync(guard.Token);
            var macroTask = MacroCollector.CollectAsync(guard.Token);
            var contextTask = ProcessContextCollector.CollectAsync(guard.Token);
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
            var errors = forensic.Errors.Concat(browser.Errors).ToList();
            var report = new ScanReport(1, session.SteamId, Version, buildHash, started, now, admin,
                new(true, ["processes", "system", "services_drivers", "persistence", "security_posture", "runtime_security", "dma_devices", "tamper_indicators", "loaded_modules", "persistence_hooks", "recent_executables", "historical_execution", "browser_history", "browser_matched_urls", "external_process_access", "macro_scripts", "process_context", "cleanup", "device_identity", "transfer"]),
                modules, evidence, errors, DeviceIdentityCollector.Collect());
            guard.Token.ThrowIfCancellationRequested();
            SetStatus("Зашифровано передаємо звіт WARDOGS…", "НАДСИЛАННЯ", "#FFD83D");
            Progress.Value = 85;
            var accepted = await _api.SubmitAsync(ApiBase, session.IncidentId, session.UploadToken, report, guard.Token);
            Progress.Value = 100;
            SetStatus($"Звіт прийнято · {accepted.Status} · № {accepted.ReportId}", "ЗАВЕРШЕНО", "#55D68A");
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
        OneTimeCode.IsEnabled = enabled;
        ConsentProcesses.IsEnabled = enabled; ConsentSystem.IsEnabled = enabled; ConsentTransfer.IsEnabled = enabled;
        UpdateStartButtonState();
    }

    private void SetStatus(string text, string badge, string color)
    {
        Status.Text = text;
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
