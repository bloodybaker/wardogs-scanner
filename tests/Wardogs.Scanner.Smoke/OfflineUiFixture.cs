using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Wardogs.Scanner;

static class OfflineUiFixture
{
    public static void Run(string folder)
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                var app = new App();
                app.InitializeComponent();
                var window = new MainWindow();
                var start = (Button)window.FindName("StartButton");
                foreach (var name in new[] { "ConsentProcesses", "ConsentSystem", "ConsentTransfer" })
                    ((CheckBox)window.FindName(name)).IsChecked = true;
                if (start.IsEnabled) throw new Exception("Online mode requires code");
                ((Button)window.FindName("OfflineButton")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                if (!start.IsEnabled) throw new Exception("Offline scan must work without code");
                var content = (FrameworkElement)window.Content;
                Directory.CreateDirectory(folder);
                void Capture(string filename, int width, int height)
                {
                    content.Measure(new Size(width, height));
                    content.Arrange(new Rect(0, 0, width, height));
                    content.UpdateLayout();
                    var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
                    bitmap.Render(content);
                    var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
                    using var output = File.Create(Path.Combine(folder, filename)); encoder.Save(output);
                }
                Capture("scanner-offline.png", 960, 760);
                Capture("scanner-offline-compact.png", 820, 660);
                ((TextBlock)window.FindName("Status")).Text = "JSON збережено. Передайте файл адміністратору.\nДокументи\\WARDOGS\\Reports\\WARDOGS-example.json";
                ((Button)window.FindName("SavedReportButton")).Visibility = Visibility.Visible;
                content.Measure(new Size(960, 760)); content.Arrange(new Rect(0, 0, 960, 760)); content.UpdateLayout();
                ((ScrollViewer)window.FindName("ReportScroll")).ScrollToEnd();
                Capture("scanner-saved.png", 960, 760);
                ((Button)window.FindName("OfflineButton")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                if (start.IsEnabled) throw new Exception("Switching back requires code again");
                window.Close();
                Console.WriteLine("PASS: offline toggle, consent, code-free start, return to online, WPF previews");
            }
            catch (Exception ex) { failure = ex; }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start(); thread.Join();
        if (failure != null) throw failure;
    }
}
