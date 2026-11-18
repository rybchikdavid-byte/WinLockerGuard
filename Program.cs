using System;
using System.Diagnostics;
using System.Drawing;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;

namespace WinLockerGuard
{
    internal static class Program
    {
        private const string MutexName = @"Local\WinLockerGuard_v1";

        [STAThread]
        private static void Main(string[] args)
        {
            bool ensure = args != null && args.Length > 0 &&
                          string.Equals(args[0], "--ensure", StringComparison.OrdinalIgnoreCase);
            bool created;
            using (Mutex mutex = new Mutex(true, MutexName, out created))
            {
                if (!created)
                {
                    return;
                }
                if (ensure)
                {
                    try
                    {
                        string exe = Assembly.GetExecutingAssembly().Location;
                        ProcessStartInfo psi = new ProcessStartInfo(exe);
                        psi.UseShellExecute = true;
                        psi.WindowStyle = ProcessWindowStyle.Hidden;
                        Process.Start(psi);
                    }
                    catch
                    {
                    }
                    return;
                }

                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                using (Guard guard = new Guard())
                {
                    guard.Start();
                    Application.Run(new TrayContext(guard));
                }
            }
        }
    }

    internal sealed class TrayContext : ApplicationContext
    {
        private readonly NotifyIcon icon;
        private readonly Guard guard;

        public TrayContext(Guard guard)
        {
            this.guard = guard;
            if (!guard.Settings.ShowTray)
            {
                return;
            }

            ContextMenuStrip menu = new ContextMenuStrip();
            menu.Items.Add("Проверить сейчас", null, delegate { guard.ScanOnce(); });
            menu.Items.Add("Журнал", null, delegate { Open(guard.LogPath); });
            menu.Items.Add("Карантин", null, delegate { Open(guard.QuarantineDir); });
            menu.Items.Add("Очистить карантин", null, delegate { ClearQuarantine(); });

            icon = new NotifyIcon();
            icon.Icon = SystemIcons.Application;
            icon.Text = "WinLockerGuard: защита включена";
            icon.ContextMenuStrip = menu;
            icon.Visible = true;
        }

        private void ClearQuarantine()
        {
            DialogResult r = MessageBox.Show(
                "Удалить все файлы из карантина навсегда?",
                "WinLockerGuard",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);
            if (r == DialogResult.Yes)
            {
                int n = guard.ClearQuarantine();
                MessageBox.Show("Удалено файлов: " + n, "WinLockerGuard",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private static void Open(string path)
        {
            try
            {
                if (System.IO.File.Exists(path) || System.IO.Directory.Exists(path))
                {
                    Process.Start(path);
                    return;
                }
                if (System.IO.Path.HasExtension(path))
                {
                    System.IO.File.WriteAllText(path, "");
                }
                else
                {
                    System.IO.Directory.CreateDirectory(path);
                }
                Process.Start(path);
            }
            catch
            {
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && icon != null)
            {
                icon.Visible = false;
                icon.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    internal sealed class Settings
    {
        public bool PermanentDelete;
        public int ScanIntervalMs = 700;
        public int AutostartScanSeconds = 5;
        public bool ShowTray = true;
        public bool DetectPrankFullscreen = true;

        public static Settings Load(string path)
        {
            Settings s = new Settings();
            try
            {
                if (!System.IO.File.Exists(path))
                {
                    return s;
                }
                foreach (string raw in System.IO.File.ReadAllLines(path))
                {
                    string line = raw.Trim();
                    if (line.Length == 0 || line.StartsWith("#") || line.StartsWith(";"))
                    {
                        continue;
                    }
                    int eq = line.IndexOf('=');
                    if (eq <= 0)
                    {
                        continue;
                    }
                    string key = line.Substring(0, eq).Trim().ToLowerInvariant();
                    string val = line.Substring(eq + 1).Trim();
                    if (key == "permanentdelete")
                    {
                        s.PermanentDelete = IsOn(val);
                    }
                    else if (key == "showtray")
                    {
                        s.ShowTray = IsOn(val);
                    }
                    else if (key == "scanintervalms")
                    {
                        int v;
                        if (int.TryParse(val, out v))
                        {
                            s.ScanIntervalMs = Math.Max(200, Math.Min(5000, v));
                        }
                    }
                    else if (key == "autostartscanseconds")
                    {
                        int v;
                        if (int.TryParse(val, out v))
                        {
                            s.AutostartScanSeconds = Math.Max(2, Math.Min(3600, v));
                        }
                    }
                    else if (key == "detectprankfullscreen")
                    {
                        s.DetectPrankFullscreen = IsOn(val);
                    }
                }
            }
            catch
            {
            }
            return s;
        }

        private static bool IsOn(string v)
        {
            v = v.Trim().ToLowerInvariant();
            return v == "1" || v == "true" || v == "yes" || v == "on" || v == "да";
        }
    }
}
