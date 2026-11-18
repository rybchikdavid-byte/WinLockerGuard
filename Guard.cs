using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace WinLockerGuard
{
    internal sealed partial class Guard : IDisposable
    {
        private readonly Settings settings;
        private readonly string baseDir;
        private readonly string exeDir;
        private readonly string quarantineDir;
        private readonly string logPath;
        private readonly object logLock = new object();
        private readonly Dictionary<int, long> handled = new Dictionary<int, long>();
        private readonly Dictionary<string, bool> signedCache = new Dictionary<string, bool>();
        private readonly Dictionary<string, DateTime> signedStamp = new Dictionary<string, DateTime>();
        private readonly List<string> allow = new List<string>();

        private System.Threading.Timer timer;
        private int scanning;
        private long lastAutostartScan;
        private long lastProcessScan;
        private long lastAllowLoad;
        private long pausedUntil;
        private readonly int myPid = Process.GetCurrentProcess().Id;

        internal Guard()
        {
            string dirExe = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            exeDir = dirExe;
            settings = Settings.Load(Path.Combine(exeDir, "settings.ini"));

            string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string dir = Path.Combine(programData, "WinLockerGuard");
            try
            {
                Directory.CreateDirectory(dir);
            }
            catch
            {
                dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "WinLockerGuard");
                try
                {
                    Directory.CreateDirectory(dir);
                }
                catch
                {
                }
            }
            baseDir = dir;
            quarantineDir = Path.Combine(baseDir, "Quarantine");
            logPath = Path.Combine(baseDir, "guard.log");
            try
            {
                Directory.CreateDirectory(quarantineDir);
            }
            catch
            {
            }
        }

        internal Settings Settings
        {
            get { return settings; }
        }

        internal string LogPath
        {
            get { return logPath; }
        }

        internal string QuarantineDir
        {
            get { return quarantineDir; }
        }

        internal void Start()
        {
            Log("===== Варгуард 1.3 запущен =====");
            Log("Windows " + Environment.OSVersion.VersionString + ", каталог " + baseDir);
            Log("Режим: " + (settings.PermanentDelete ? "удалять навсегда" : "карантин") +
                ", интервал " + settings.ScanIntervalMs + " мс");
            ScanOnce();
            timer = new System.Threading.Timer(Tick, null, settings.ScanIntervalMs,
                settings.ScanIntervalMs);
        }

        private void Tick(object state)
        {
            try
            {
                ScanOnce();
            }
            catch (Exception ex)
            {
                Log("Ошибка таймера: " + ex.Message);
            }
        }

        internal void ScanOnce()
        {
            if (Interlocked.Exchange(ref scanning, 1) == 1)
            {
                return;
            }
            try
            {
                if (IsPaused)
                {
                    return;
                }
                ScanProcesses();
                ScanWindows();
                long now = NowMs();
                if (now - lastAutostartScan >= settings.AutostartScanSeconds * 1000L)
                {
                    lastAutostartScan = now;
                    ScanAutostart();
                }
            }
            catch (Exception ex)
            {
                Log("Ошибка проверки: " + ex);
            }
            finally
            {
                Interlocked.Exchange(ref scanning, 0);
            }
        }

        private void ScanProcesses()
        {
            long now = NowMs();
            if (now - lastProcessScan < 2000L)
            {
                return;
            }
            lastProcessScan = now;

            Process[] all = Process.GetProcesses();
            for (int i = 0; i < all.Length; i++)
            {
                Process p = all[i];
                try
                {
                    if (p.Id <= 4 || p.Id == myPid)
                    {
                        continue;
                    }
                    string name = p.ProcessName;
                    string path;
                    try
                    {
                        path = p.MainModule.FileName;
                    }
                    catch
                    {
                        continue;
                    }
                    if (string.IsNullOrEmpty(path) || Detect.IsProtectedLocation(path) ||
                        IsOwnPath(path) || IsAllowlisted(name, path))
                    {
                        continue;
                    }

                    if (Detect.LooksLikeBadName(name + ".exe") || Detect.LooksLikeBadName(path))
                    {
                        Neutralize((uint)p.Id, "имя процесса: " + name + " (" + path + ")");
                        continue;
                    }

                    if (!settings.Aggressive || !Detect.IsUserWritable(path))
                    {
                        continue;
                    }
                    if (IsSignedCached(path))
                    {
                        continue;
                    }

                    string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                    string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                    string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                    string commonAppData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

                    bool fromTemp = Detect.StartsWithDir(path, Path.GetTempPath());
                    bool underProfile = Detect.StartsWithDir(path, profile);
                    bool underAppData = Detect.StartsWithDir(path, appData) ||
                                        Detect.StartsWithDir(path, localAppData) ||
                                        Detect.StartsWithDir(path, commonAppData);

                    if (fromTemp || (underProfile && !underAppData) || !HasVersionInfo(path))
                    {
                        Neutralize((uint)p.Id,
                            "неподписанный exe" +
                            (fromTemp ? " из Temp" : underProfile && !underAppData ? " из пользовательской папки" : " без данных о версии") +
                            ": " + path);
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

        private bool IsSignedCached(string path)
        {
            DateTime stamp;
            try
            {
                stamp = File.GetLastWriteTimeUtc(path);
            }
            catch
            {
                return false;
            }
            lock (signedCache)
            {
                DateTime old;
                bool known;
                if (signedStamp.TryGetValue(path, out old) && old == stamp &&
                    signedCache.TryGetValue(path, out known))
                {
                    return known;
                }
                bool signed = Detect.IsSigned(path);
                signedStamp[path] = stamp;
                signedCache[path] = signed;
                if (signedCache.Count > 4096)
                {
                    signedCache.Clear();
                    signedStamp.Clear();
                }
                return signed;
            }
        }

        private void LoadAllowList()
        {
            long now = NowMs();
            if (now - lastAllowLoad < 5000L)
            {
                return;
            }
            lastAllowLoad = now;
            allow.Clear();
            try
            {
                string file = Path.Combine(exeDir, "allow.txt");
                if (!File.Exists(file))
                {
                    return;
                }
                foreach (string raw in File.ReadAllLines(file))
                {
                    string line = raw.Trim();
                    if (line.Length == 0 || line.StartsWith("#") || line.StartsWith(";"))
                    {
                        continue;
                    }
                    allow.Add(line.ToLowerInvariant());
                }
            }
            catch
            {
            }
        }

        private bool IsAllowlisted(string name, string path)
        {
            LoadAllowList();
            if (allow.Count == 0)
            {
                return false;
            }
            string n = (name ?? "").ToLowerInvariant();
            if (!n.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                n = n + ".exe";
            }
            string p = (path ?? "").ToLowerInvariant();
            for (int i = 0; i < allow.Count; i++)
            {
                string a = allow[i];
                if (a == n || a == p)
                {
                    return true;
                }
                if (a.EndsWith("\\") && p.StartsWith(a, StringComparison.Ordinal))
                {
                    return true;
                }
                if (a.IndexOf('\\') >= 0 && p.StartsWith(a, StringComparison.Ordinal))
                {
                    return true;
                }
            }
            return false;
        }

        internal void Pause(int minutes)
        {
            pausedUntil = NowMs() + minutes * 60000L;
            Log("Пауза защиты на " + minutes + " мин (установка программ)");
        }

        internal void Resume()
        {
            pausedUntil = 0;
            Log("Защита продолжена");
        }

        internal bool IsPaused
        {
            get { return NowMs() < pausedUntil; }
        }

        private void ScanWindows()
        {
            List<Detection> found = new List<Detection>();
            Native.EnumWindows(delegate(IntPtr hwnd, IntPtr lparam)
            {
                try
                {
                    CheckWindow(hwnd, found);
                }
                catch
                {
                }
                return true;
            }, IntPtr.Zero);

            for (int i = 0; i < found.Count; i++)
            {
                try
                {
                    Neutralize(found[i].Pid, found[i].Reason);
                }
                catch (Exception ex)
                {
                    Log("Не удалось обезвредить pid " + found[i].Pid + ": " + ex.Message);
                }
            }
        }

        private void CheckWindow(IntPtr hwnd, List<Detection> found)
        {
            if (!Native.IsWindowVisible(hwnd))
            {
                return;
            }
            if (Native.GetWindow(hwnd, Native.GW_OWNER) != IntPtr.Zero)
            {
                return;
            }
            Native.RECT r;
            if (!Native.GetWindowRect(hwnd, out r))
            {
                return;
            }
            if (r.Right - r.Left < 320 || r.Bottom - r.Top < 200)
            {
                return;
            }
            if (!Detect.IsFullscreen(hwnd, r))
            {
                return;
            }

            bool topmost = Detect.IsTopmost(hwnd);
            string text = Detect.CollectWindowText(hwnd);
            bool veryStrong = false;
            bool locker = text.Length >= 8 && Detect.LooksLikeLocker(text, out veryStrong);
            string reason;

            if (locker)
            {
                if (!topmost && !veryStrong)
                {
                    return;
                }
                reason = (topmost ? "topmost, " : "") + Truncate(text, 180);
            }
            else
            {
                if (!topmost)
                {
                    return;
                }
                uint candidate;
                Native.GetWindowThreadProcessId(hwnd, out candidate);
                string path = GetProcessPath(candidate);
                if (string.IsNullOrEmpty(path) || Detect.IsProtectedLocation(path) ||
                    !Detect.IsUserWritable(path) || IsOwnPath(path))
                {
                    return;
                }
                bool badName = Detect.LooksLikeBadName(path);
                bool hasInfo = HasVersionInfo(path);
                if (hasInfo && !badName)
                {
                    return;
                }
                bool dark = settings.DetectPrankFullscreen && GuardVisual.IsMostlyDark(hwnd, r);
                bool tempExe = IsTempFullscreenExe(path);
                if (!badName && !dark && !tempExe)
                {
                    return;
                }
                reason = "полноэкранное окно поверх всех: " + path +
                         (dark ? ", тёмный экран (пранк/винлокер)" : "") +
                         (tempExe ? ", exe из Temp без версии" : "") +
                         (badName ? ", подозрительное имя" : "");
            }

            uint pid;
            Native.GetWindowThreadProcessId(hwnd, out pid);
            if (pid == 0)
            {
                return;
            }
            for (int i = 0; i < found.Count; i++)
            {
                if (found[i].Pid == pid)
                {
                    return;
                }
            }
            found.Add(new Detection(pid, reason));
        }

        private static string GetProcessPath(uint pid)
        {
            if (pid == 0)
            {
                return null;
            }
            try
            {
                using (Process p = Process.GetProcessById((int)pid))
                {
                    return p.MainModule.FileName;
                }
            }
            catch
            {
                return null;
            }
        }

        private static bool HasVersionInfo(string path)
        {
            try
            {
                FileVersionInfo info = FileVersionInfo.GetVersionInfo(path);
                return !string.IsNullOrEmpty(info.CompanyName) ||
                       !string.IsNullOrEmpty(info.FileVersion) ||
                       !string.IsNullOrEmpty(info.ProductName);
            }
            catch
            {
                return false;
            }
        }

        private static bool IsTempFullscreenExe(string path)
        {
            if (string.IsNullOrEmpty(path) || Detect.IsProtectedLocation(path))
            {
                return false;
            }
            try
            {
                return Detect.StartsWithDir(path, Path.GetTempPath()) && !HasVersionInfo(path);
            }
            catch
            {
                return false;
            }
        }

        private void Neutralize(uint pid, string reason)
        {
            if (pid <= 4L)
            {
                return;
            }
            int ipid = (int)pid;
            if (ipid == Process.GetCurrentProcess().Id)
            {
                return;
            }

            Process proc;
            try
            {
                proc = Process.GetProcessById(ipid);
            }
            catch
            {
                return;
            }

            using (proc)
            {
                string name = "";
                string path = null;
                try
                {
                    name = proc.ProcessName;
                }
                catch
                {
                }
                try
                {
                    path = proc.MainModule.FileName;
                }
                catch
                {
                }

                if (IsWhitelisted(name, ipid, path))
                {
                    Log("Пропуск системного процесса: " + name + " (" + ipid + ")");
                    return;
                }

                long now = NowMs();
                lock (handled)
                {
                    long last;
                    if (handled.TryGetValue(ipid, out last) && now - last < 60000L)
                    {
                        return;
                    }
                    handled[ipid] = now;
                    if (handled.Count > 512)
                    {
                        List<int> stale = new List<int>();
                        foreach (KeyValuePair<int, long> kv in handled)
                        {
                            if (now - kv.Value > 300000L)
                            {
                                stale.Add(kv.Key);
                            }
                        }
                        for (int i = 0; i < stale.Count; i++)
                        {
                            handled.Remove(stale[i]);
                        }
                    }
                }

                Log("ВИНЛОКЕР: pid=" + ipid + " процесс=" + name +
                    " файл=" + (path == null ? "?" : path));
                Log("Причина: " + Truncate(reason, 300));

                try { Native.BlockInput(false); } catch { }
                try { Native.ClipCursor(IntPtr.Zero); } catch { }

                KillTree(proc, ipid);

                try { Native.BlockInput(false); } catch { }
                try { Native.ClipCursor(IntPtr.Zero); } catch { }

                CleanupPersistence(path, name);

                if (!string.IsNullOrEmpty(path) && File.Exists(path))
                {
                    if (Detect.IsProtectedLocation(path))
                    {
                        Log("Файл в системной папке, не удаляю: " + path);
                    }
                    else
                    {
                        QuarantineFile(path, "winlocker: " + Truncate(reason, 120));
                    }
                }
                Log("Винлокер обезврежен: " + name + " (" + ipid + ")");
            }
        }

        private static bool IsWhitelisted(string name, int pid, string path)
        {
            if (pid <= 4)
            {
                return true;
            }
            string n = (name ?? "").ToLowerInvariant();
            string[] safe =
            {
                "system", "idle", "registry", "smss", "csrss", "wininit", "services",
                "lsass", "winlogon", "svchost", "dwm", "explorer", "fontdrvhost",
                "spoolsv", "taskhostw", "sihost", "ctfmon", "runtimebroker",
                "shellexperiencehost", "startmenuexperiencehost", "searchhost",
                "searchapp", "textinputhost", "applicationframehost", "lockapp",
                "logonui", "consent", "useroobebroker", "audiodg", "wudfhost",
                "dashost", "msmpeng", "nissrv", "securityhealthservice", "sgrmbroker",
                "smartscreen", "taskmgr", "winlogerguard"
            };
            for (int i = 0; i < safe.Length; i++)
            {
                if (n == safe[i])
                {
                    return true;
                }
            }
            if (!string.IsNullOrEmpty(path) &&
                path.IndexOf("\\WinLockerGuard\\", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }
            return false;
        }

        private void KillTree(Process proc, int pid)
        {
            try
            {
                RunTool("taskkill.exe", "/F /T /PID " + pid, 6000);
            }
            catch
            {
            }
            try
            {
                if (!proc.HasExited)
                {
                    proc.Kill();
                }
            }
            catch
            {
            }
            try
            {
                proc.WaitForExit(2000);
            }
            catch
            {
            }
        }

        private void QuarantineFile(string path, string reason)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path))
            {
                return;
            }
            string destination = null;
            try
            {
                Directory.CreateDirectory(quarantineDir);
                string safeName = Path.GetFileName(path);
                if (safeName.Length > 80)
                {
                    safeName = safeName.Substring(0, 80);
                }
                string stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss_fff");
                destination = Path.Combine(quarantineDir, stamp + "_" + safeName + ".quarantine");
                int n = 1;
                while (File.Exists(destination))
                {
                    destination = Path.Combine(quarantineDir, stamp + "_" + n + "_" + safeName + ".quarantine");
                    n++;
                }
                try
                {
                    File.SetAttributes(path, FileAttributes.Normal);
                }
                catch
                {
                }

                bool moved = false;
                for (int i = 0; i < 8 && !moved; i++)
                {
                    try
                    {
                        File.Move(path, destination);
                        moved = true;
                    }
                    catch
                    {
                        Thread.Sleep(250);
                    }
                }
                if (!moved)
                {
                    try
                    {
                        File.Copy(path, destination, true);
                        moved = true;
                    }
                    catch
                    {
                    }
                    if (moved)
                    {
                        try
                        {
                            File.Delete(path);
                        }
                        catch
                        {
                            ScheduleDelete(path);
                        }
                    }
                }

                if (!moved)
                {
                    ScheduleDelete(path);
                    Log("Не удалось перенести в карантин: " + path);
                    return;
                }

                try
                {
                    File.WriteAllText(destination + ".txt",
                        "Оригинал: " + path + Environment.NewLine +
                        "Причина: " + reason + Environment.NewLine +
                        "Время: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + Environment.NewLine,
                        Encoding.UTF8);
                }
                catch
                {
                }
                Log("В карантин: " + path + " -> " + destination);

                if (settings.PermanentDelete)
                {
                    try
                    {
                        File.Delete(destination);
                        Log("Удалён навсегда: " + path);
                    }
                    catch
                    {
                        ScheduleDelete(destination);
                    }
                }
            }
            catch (Exception ex)
            {
                Log("Ошибка карантина (" + path + "): " + ex.Message);
                if (destination != null)
                {
                    try { File.Delete(destination); } catch { }
                }
            }
        }

        private void ScheduleDelete(string path)
        {
            try
            {
                Native.MoveFileEx(path, null, Native.MOVEFILE_DELAY_UNTIL_REBOOT);
                Log("Удаление при перезагрузке: " + path);
            }
            catch
            {
            }
        }

        internal void Shutdown()
        {
            try
            {
                string dir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                File.WriteAllText(Path.Combine(dir, "stopped.flag"), DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            }
            catch
            {
            }
            Log("Остановка по команде пользователя");
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

        internal int ClearQuarantine()
        {
            int count = 0;
            try
            {
                if (!Directory.Exists(quarantineDir))
                {
                    return 0;
                }
                foreach (string file in Directory.GetFiles(quarantineDir))
                {
                    try
                    {
                        File.SetAttributes(file, FileAttributes.Normal);
                        File.Delete(file);
                        count++;
                    }
                    catch
                    {
                        ScheduleDelete(file);
                    }
                }
            }
            catch (Exception ex)
            {
                Log("Ошибка очистки карантина: " + ex.Message);
            }
            Log("Очистка карантина: удалено " + count + " файлов");
            return count;
        }

        private void Log(string message)
        {
            lock (logLock)
            {
                try
                {
                    if (File.Exists(logPath) && new FileInfo(logPath).Length > 1024 * 1024)
                    {
                        try
                        {
                            if (File.Exists(logPath + ".old"))
                            {
                                File.Delete(logPath + ".old");
                            }
                            File.Move(logPath, logPath + ".old");
                        }
                        catch
                        {
                        }
                    }
                    File.AppendAllText(logPath,
                        DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + message + Environment.NewLine,
                        Encoding.UTF8);
                }
                catch
                {
                }
            }
        }

        internal static string RunTool(string file, string args, int timeoutMs)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(file, args);
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                try
                {
                    psi.StandardOutputEncoding = Encoding.GetEncoding(
                        CultureInfo.CurrentCulture.TextInfo.OEMCodePage);
                }
                catch
                {
                }
                using (Process p = Process.Start(psi))
                {
                    string output = p.StandardOutput.ReadToEnd();
                    string error = p.StandardError.ReadToEnd();
                    if (!p.WaitForExit(timeoutMs))
                    {
                        try { p.Kill(); } catch { }
                    }
                    return output + error;
                }
            }
            catch
            {
                return "";
            }
        }

        private static long NowMs()
        {
            return DateTime.UtcNow.Ticks / TimeSpan.TicksPerMillisecond;
        }

        private static string Truncate(string text, int max)
        {
            if (text == null)
            {
                return "";
            }
            text = text.Replace('\r', ' ').Replace('\n', ' ').Trim();
            return text.Length <= max ? text : text.Substring(0, max) + "…";
        }

        public void Dispose()
        {
            if (timer != null)
            {
                timer.Dispose();
                timer = null;
            }
            Log("===== Варгуард остановлен =====");
        }

        private sealed class Detection
        {
            internal readonly uint Pid;
            internal readonly string Reason;

            internal Detection(uint pid, string reason)
            {
                Pid = pid;
                Reason = reason;
            }
        }
    }
}
