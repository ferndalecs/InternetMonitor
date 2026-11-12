// Internet Monitor - entry point.

using System;
using System.IO;
using System.Net;
using System.Reflection;
using System.Runtime.Versioning;
using System.Threading;
using System.Windows.Forms;

[assembly: AssemblyTitle("Internet Monitor")]
[assembly: AssemblyDescription("Monitors internet and web-filter availability and produces an uptime report.")]
[assembly: AssemblyProduct("Internet Monitor")]
[assembly: AssemblyCompany("IT Support")]
[assembly: AssemblyCopyright("")]
[assembly: AssemblyVersion("2.4.1.0")]
[assembly: AssemblyFileVersion("2.4.1.0")]
// Opts in to modern .NET Framework behaviour (operating-system default TLS versions, etc.).
[assembly: TargetFramework(".NETFramework,Version=v4.8", FrameworkDisplayName = ".NET Framework 4.8")]

namespace InternetMonitor
{
    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException += delegate(object s, ThreadExceptionEventArgs e) { Crash(e.Exception); };
            AppDomain.CurrentDomain.UnhandledException += delegate(object s, UnhandledExceptionEventArgs e) { Crash(e.ExceptionObject as Exception); };

            // One copy per signed-in user: two copies would double the load and interleave the log.
            bool first;
            using (Mutex mutex = new Mutex(true, "Local\\InternetMonitor.SingleInstance", out first))
            {
                if (!first)
                {
                    MessageBox.Show("Internet Monitor is already running.\n\nLook for it on the taskbar.", AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return 1;
                }

                ConfigureNetworking();
                string exeDir = AppDomain.CurrentDomain.BaseDirectory;
                Settings settings = Settings.Load(exeDir);
                // Say honestly what we are, so a site's administrators can see it is a monitor and who to ask.
                HttpProbe.UserAgent = "InternetMonitor/" + AppInfo.Version + " (school connectivity monitor"
                    + (settings.Contact.Length > 0 ? "; contact " + settings.Contact : "") + ")";
                Wifi.Decide(settings.WifiDetails);
                using (LogStore store = new LogStore(settings, exeDir))
                {
                    Application.Run(new MainForm(settings, store, args));
                }
                GC.KeepAlive(mutex);
            }
            return 0;
        }

        private static void ConfigureNetworking()
        {
            ThreadPool.SetMinThreads(24, 8);
            ServicePointManager.DefaultConnectionLimit = 32;
            ServicePointManager.Expect100Continue = false;
            ServicePointManager.DnsRefreshTimeout = 0;      // look names up every time; that is part of the test
            // 0 means "use the Windows defaults", which is what we want. Only step in on old configurations.
            if (ServicePointManager.SecurityProtocol != 0)
                ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            try
            {
                // Sign in to an authenticating proxy as the logged-on user, like a browser does.
                IWebProxy proxy = WebRequest.DefaultWebProxy;
                if (proxy != null) proxy.Credentials = CredentialCache.DefaultCredentials;
            }
            catch { }
        }

        private static void Crash(Exception ex)
        {
            string text = ex == null ? "Unknown error" : ex.ToString();
            string file = Path.Combine(Path.GetTempPath(), "InternetMonitor-error.txt");
            try { File.WriteAllText(file, DateTime.Now + Environment.NewLine + text); } catch { }
            MessageBox.Show("Internet Monitor ran into a problem and needs to close.\n\n" + (ex == null ? "" : ex.Message)
                + "\n\nDetails were saved to:\n" + file, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
            Environment.Exit(2);
        }
    }
}
