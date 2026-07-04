using System.Windows;
using Velopack;

namespace SerpiumVPN
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : System.Windows.Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            VelopackApp.Build().Run();
            base.OnStartup(e);
        }
    }
}
