using System;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using InputKey = System.Windows.Input.Key;
using InputKeyEventArgs = System.Windows.Input.KeyEventArgs;
using MediaBrush = System.Windows.Media.Brush;
using MediaBrushConverter = System.Windows.Media.BrushConverter;

namespace SerpiumVPN;

public enum SerpiumNoticeKind
{
    Success,
    Information,
    Warning,
    Error
}

public partial class SerpiumNoticeDialog : Window
{
    private SerpiumNoticeDialog(
        string context,
        string title,
        string subtitle,
        string body,
        string footer,
        SerpiumNoticeKind kind)
    {
        InitializeComponent();

        HeaderContextText.Text =
            "  ·  " + context;

        NoticeTitleText.Text = title;
        NoticeSubtitleText.Text = subtitle;
        NoticeBodyText.Text = body;
        FooterText.Text = footer;

        ApplyKind(kind);
    }

    public static void Show(
        Window owner,
        string context,
        string title,
        string subtitle,
        string body,
        string footer,
        SerpiumNoticeKind kind)
    {
        ArgumentNullException.ThrowIfNull(owner);

        SerpiumNoticeDialog dialog = new(
            context,
            title,
            subtitle,
            body,
            footer,
            kind)
        {
            Owner = owner
        };

        dialog.ShowDialog();
    }

    private void ApplyKind(
        SerpiumNoticeKind kind)
    {
        string icon;
        string background;
        string border;
        string foreground;

        switch (kind)
        {
            case SerpiumNoticeKind.Success:
                icon = "✓";
                background = "#123A2A";
                border = "#288D5D";
                foreground = "#67EAA7";
                break;

            case SerpiumNoticeKind.Warning:
                icon = "!";
                background = "#4A3710";
                border = "#C08B22";
                foreground = "#FFE09A";
                break;

            case SerpiumNoticeKind.Error:
                icon = "×";
                background = "#482027";
                border = "#AD4655";
                foreground = "#FF8996";
                break;

            default:
                icon = "i";
                background = "#172E4A";
                border = "#3677B8";
                foreground = "#8CC8FF";
                break;
        }

        NoticeIconText.Text = icon;
        NoticeIconBorder.Background =
            BrushFromHex(background);
        NoticeIconBorder.BorderBrush =
            BrushFromHex(border);
        NoticeIconText.Foreground =
            BrushFromHex(foreground);
    }

    private static MediaBrush BrushFromHex(
        string value)
    {
        return (MediaBrush)new MediaBrushConverter()
            .ConvertFromString(value)!;
    }

    private void Close_Click(
        object sender,
        RoutedEventArgs e)
    {
        DialogResult = true;
    }

    private void Window_KeyDown(
        object sender,
        InputKeyEventArgs e)
    {
        if (e.Key != InputKey.Escape)
            return;

        e.Handled = true;
        DialogResult = true;
    }

    private void Header_MouseLeftButtonDown(
        object sender,
        MouseButtonEventArgs e)
    {
        if (e.ChangedButton != MouseButton.Left)
            return;

        try
        {
            DragMove();
        }
        catch
        {
            // Ignore a drag race if the notice closes simultaneously.
        }
    }
}
