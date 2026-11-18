using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace WinLockerGuard
{
    internal static class Program
    {
        private const string MutexName = @"Local\WinLockerGuard_v1";
        private const string WatchdogMutexName = @"Local\WinLockerGuard_watchdog_v1";
        private const string Version = "1.2";

        [STAThread]
        private static void Main(string[] args)
        {
            bool ensure = HasArg(args, "--ensure");
            bool autostart = HasArg(args, "--autostart");
            bool silent = ensure || autostart;

            if (HasArg(args, "--watchdog"))
            {
                RunWatchdog();
                return;
            }

            string self = Assembly.GetExecutingAssembly().Location;
            string installDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "WinLockerGuard");

            // Запустили из папки с архивом — тихо переезжаем в свою папку,
            // без установщика, без бата и без вопросов.
            if (!InInstallDir(self, installDir))
            {
                if (TryMigrate(self, installDir, silent))
                {
                    return;
                }
            }

            bool created;
            using (Mutex mutex = new Mutex(true, MutexName, out created))
            {
                if (!created)
                {
                    if (!silent)
                    {
                        ShowHello(null);
                    }
                    return;
                }

                if (ensure)
                {
                    try
                    {
                        ProcessStartInfo psi = new ProcessStartInfo(self);
                        psi.UseShellExecute = true;
                        psi.WindowStyle = ProcessWindowStyle.Hidden;
                        psi.Arguments = "--autostart";
                        Process.Start(psi);
                    }
                    catch
                    {
                    }
                    return;
                }

                ClearStopFlag();

                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                using (Guard guard = new Guard())
                {
                    guard.Start();
                    StartWatchdog(self);
                    if (!silent)
                    {
                        ShowHello(guard);
                    }
                    Application.Run(new TrayContext(guard));
                }
            }
        }

        private static bool HasArg(string[] args, string name)
        {
            if (args == null)
            {
                return false;
            }
            for (int i = 0; i < args.Length; i++)
            {
                if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            return false;
        }

        private static bool InInstallDir(string exe, string installDir)
        {
            string dir = Path.GetDirectoryName(exe);
            if (SameDir(dir, installDir))
            {
                return true;
            }
            // администраторская установка через Install.bat — тоже «своя» папка
            string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            return SameDir(dir, Path.Combine(programData, "WinLockerGuard"));
        }

        private static bool SameDir(string a, string b)
        {
            try
            {
                return string.Equals(
                    Path.GetFullPath(a).TrimEnd('\\'),
                    Path.GetFullPath(b).TrimEnd('\\'),
                    StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        private static bool TryMigrate(string self, string installDir, bool silent)
        {
            try
            {
                Directory.CreateDirectory(installDir);
                string target = Path.Combine(installDir, "WinLockerGuard.exe");
                StopOtherInstances();

                bool copied = false;
                for (int i = 0; i < 12 && !copied; i++)
                {
                    try
                    {
                        File.Copy(self, target, true);
                        copied = true;
                    }
                    catch
                    {
                        Thread.Sleep(300);
                    }
                }
                if (!copied)
                {
                    return false;
                }

                WriteRunEntry(target);
                ProcessStartInfo psi = new ProcessStartInfo(target);
                psi.UseShellExecute = true;
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                psi.Arguments = silent ? "--autostart" : "";
                Process.Start(psi);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static void StopOtherInstances()
        {
            try
            {
                int me = Process.GetCurrentProcess().Id;
                foreach (Process p in Process.GetProcessesByName("WinLockerGuard"))
                {
                    try
                    {
                        if (p.Id != me)
                        {
                            p.Kill();
                        }
                    }
                    catch
                    {
                    }
                    finally
                    {
                        p.Dispose();
                    }
                }
            }
            catch
            {
            }
        }

        private static void WriteRunEntry(string exe)
        {
            try
            {
                using (RegistryKey run = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Run", true))
                {
                    if (run == null)
                    {
                        return;
                    }
                    run.SetValue("WinLockerGuard", "\"" + exe + "\" --autostart");
                }
            }
            catch
            {
            }
        }

        private static void StartWatchdog(string exe)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(exe);
                psi.UseShellExecute = true;
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                psi.Arguments = "--watchdog";
                Process.Start(psi);
            }
            catch
            {
            }
        }

        private static void RunWatchdog()
        {
            bool created;
            using (Mutex mine = new Mutex(true, WatchdogMutexName, out created))
            {
                if (!created)
                {
                    return;
                }
                string self = Assembly.GetExecutingAssembly().Location;
                while (true)
                {
                    Thread.Sleep(15000);
                    if (File.Exists(StopFlag(self)))
                    {
                        return;
                    }
                    if (IsGuardRunning())
                    {
                        continue;
                    }
                    try
                    {
                        ProcessStartInfo psi = new ProcessStartInfo(self);
                        psi.UseShellExecute = true;
                        psi.WindowStyle = ProcessWindowStyle.Hidden;
                        psi.Arguments = "--autostart";
                        Process.Start(psi);
                    }
                    catch
                    {
                    }
                    Thread.Sleep(10000);
                }
            }
        }

        private static bool IsGuardRunning()
        {
            try
            {
                using (Mutex m = Mutex.OpenExisting(MutexName))
                {
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        private static string StopFlag(string exe)
        {
            try
            {
                return Path.Combine(Path.GetDirectoryName(exe), "stopped.flag");
            }
            catch
            {
                return "stopped.flag";
            }
        }

        private static void ClearStopFlag()
        {
            try
            {
                string flag = StopFlag(Assembly.GetExecutingAssembly().Location);
                if (File.Exists(flag))
                {
                    File.Delete(flag);
                }
            }
            catch
            {
            }
        }

        private static void ShowHello(Guard guard)
        {
            try
            {
                string dir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "WinLockerGuard");
                Directory.CreateDirectory(dir);
                string letter = Path.Combine(dir, "Привет от Варгуарда.txt");
                string log = guard != null ? guard.LogPath : Path.Combine(dir, "guard.log");
                string quarantine = guard != null ? guard.QuarantineDir : Path.Combine(dir, "Quarantine");

                StringBuilder text = new StringBuilder();
                text.AppendLine("Привет, я Варгуард.");
                text.AppendLine();
                text.AppendLine("Короче, это я помогаю спасать от винлокеров и проверяю дружбу с Ратником.");
                text.AppendLine("Особенно всё, что связано с TikTok: эта популярная винлокеро-хакерская");
                text.AppendLine("группировка, бот Опко-4 и те самые модификации с надписью «Вас заметили».");
                text.AppendLine();
                text.AppendLine("Я уже запущен и работаю в фоне, без установщика и без вопросов.");
                text.AppendLine("Проверяю экран каждые 0,7 секунды и сам гашу то, что похоже на винлокер:");
                text.AppendLine();
                text.AppendLine("  - полноэкранные окна с текстом про блокировку, полицию и выкуп;");
                text.AppendLine("  - чёрные полноэкранные пранки вроде «Вас заметили», даже если текст нарисован картинкой;");
                text.AppendLine("  - подозрительные процессы и файлы из Temp, Downloads и AppData.");
                text.AppendLine();
                text.AppendLine("При обнаружении: снимаю блокировку ввода, убиваю процесс с дочерними,");
                text.AppendLine("чищу автозапуск, задачи планировщика, службы и ярлыки, файл отправляю в карантин.");
                text.AppendLine();
                text.AppendLine("Это окно можно закрыть — я останусь работать. Значок в трее рядом с часами.");
                text.AppendLine();
                text.AppendLine("Журнал:    " + log);
                text.AppendLine("Карантин:  " + quarantine);
                text.AppendLine();
                text.AppendLine("Варгуард " + Version);
                File.WriteAllText(letter, text.ToString(), new UTF8Encoding(true));

                Process.Start("notepad.exe", "\"" + letter + "\"");
            }
            catch
            {
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
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Выход (остановить защиту)", null, delegate
            {
                guard.Shutdown();
                ExitThread();
            });

            icon = new NotifyIcon();
            icon.Icon = SystemIcons.Application;
            icon.Text = "Варгуард: защита включена";
            icon.ContextMenuStrip = menu;
            icon.Visible = true;
        }

        private void ClearQuarantine()
        {
            DialogResult r = MessageBox.Show(
                "Удалить все файлы из карантина навсегда?",
                "Варгуард",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);
            if (r == DialogResult.Yes)
            {
                int n = guard.ClearQuarantine();
                MessageBox.Show("Удалено файлов: " + n, "Варгуард",
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
