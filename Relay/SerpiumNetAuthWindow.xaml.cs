using System;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Windows;

namespace SerpiumVPN.Relay;

public partial class SerpiumNetAuthWindow : Window
{
    private string? _loginUrl;
    private string? _automaticallyOpenedUrl;
    private bool _completed;
    private bool _cancelRaised;

    public event EventHandler? CancelRequested;

    public SerpiumNetAuthWindow()
    {
        InitializeComponent();
    }

    public void SetLoginUrl(string url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            SetError("SerpiumNet returned an empty authorization URL.");
            return;
        }

        bool isNewUrl = !string.Equals(_loginUrl, url, StringComparison.Ordinal);
        _loginUrl = url;

        LoginUrlTextBox.Text = url;
        LoginUrlTextBox.Visibility = Visibility.Visible;
        OpenLoginButton.IsEnabled = true;
        CopyLoginButton.IsEnabled = true;

        if (isNewUrl &&
            !string.Equals(_automaticallyOpenedUrl, url, StringComparison.Ordinal))
        {
            if (!TryOpenLoginPage(url))
            {
                Activate();
                return;
            }

            _automaticallyOpenedUrl = url;
            StatusTextBlock.Text =
                "Браузер открыт. Подтвердите устройство — подключение продолжится автоматически.";
        }
        else
        {
            StatusTextBlock.Text =
                "Откройте страницу входа и подтвердите устройство. Подключение продолжится автоматически.";
        }

        StatusTextBlock.Foreground = System.Windows.Media.Brushes.Goldenrod;
        Activate();
    }

    public async void SetConnected(string ip)
    {
        _completed = true;
        StatusTextBlock.Text = $"Авторизация выполнена. SerpiumNet подключён: {ip}";
        StatusTextBlock.Foreground = System.Windows.Media.Brushes.LightGreen;
        OpenLoginButton.IsEnabled = false;
        CopyLoginButton.IsEnabled = false;
        await Task.Delay(900);
        Close();
    }

    public void SetError(string message)
    {
        StatusTextBlock.Text = "Ошибка: " + message;
        StatusTextBlock.Foreground = System.Windows.Media.Brushes.OrangeRed;
    }

    private void OpenLoginButton_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_loginUrl))
        {
            return;
        }

        if (TryOpenLoginPage(_loginUrl))
        {
            StatusTextBlock.Text =
                "Страница входа открыта. После подтверждения подключение продолжится автоматически.";
            StatusTextBlock.Foreground = System.Windows.Media.Brushes.Goldenrod;
        }
    }

    private void CopyLoginButton_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_loginUrl))
        {
            return;
        }

        System.Windows.Clipboard.SetText(_loginUrl);
        StatusTextBlock.Text = "Ссылка скопирована. Откройте её в браузере и подтвердите устройство.";
        StatusTextBlock.Foreground = System.Windows.Media.Brushes.Goldenrod;
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e)
    {
        RaiseCancelRequestedOnce();
        Close();
    }

    protected override void OnClosed(EventArgs e)
    {
        if (!_completed)
        {
            RaiseCancelRequestedOnce();
        }

        base.OnClosed(e);
    }

    private bool TryOpenLoginPage(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo(url)
            {
                UseShellExecute = true
            });
            return true;
        }
        catch (Exception exception)
        {
            StatusTextBlock.Text =
                "Не удалось автоматически открыть браузер. Нажмите «Скопировать ссылку». " +
                exception.Message;
            StatusTextBlock.Foreground = System.Windows.Media.Brushes.OrangeRed;
            return false;
        }
    }

    private void RaiseCancelRequestedOnce()
    {
        if (_cancelRaised)
        {
            return;
        }

        _cancelRaised = true;
        CancelRequested?.Invoke(this, EventArgs.Empty);
    }
}
