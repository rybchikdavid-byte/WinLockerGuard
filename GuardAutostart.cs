using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using Microsoft.Win32;

namespace WinLockerGuard
{
    internal sealed partial class Guard
    {
        private static readonly string[] RunSubKeys =
        {
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
        };

        private void ScanAutostart()
        {
            ScanRunKey(RegistryHive.CurrentUser, RegistryView.Registry64);
            ScanRunKey(RegistryHive.CurrentUser, RegistryView.Registry32);
            ScanRunKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            ScanRunKey(RegistryHive.LocalMachine, RegistryView.Registry32);

            ScanStartupFolder(Environment.GetFolderPath(Environment.SpecialFolder.Startup));
            ScanStartupFolder(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup));
        }

        private void ScanRunKey(RegistryHive hive, RegistryView view)
        {
            try
            {
                using (RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, view))
                {
                    for (int s = 0; s < RunSubKeys.Length; s++)
                    {
                        using (RegistryKey key = baseKey.OpenSubKey(RunSubKeys[s], true))
                        {
                            if (key == null)
                            {
                                continue;
                            }
                            string[] names;
                            try
                            {
                                names = key.GetValueNames();
                            }
                            catch
                            {
                                continue;
                            }
                            for (int i = 0; i < names.Length; i++)
                            {
                                string data = null;
                                try
                                {
                                    data = key.GetValue(names[i], null,
                                        RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                                }
                                catch
                                {
                                }
                                if (string.IsNullOrEmpty(data))
                                {
                                    continue;
                                }
                                string exe = Detect.ExtractExecutable(data);
                                if (string.IsNullOrEmpty(exe) || !File.Exists(exe))
                                {
                                    continue;
                                }
                                if (IsOwnPath(exe))
                                {
                                    continue;
                                }
                                if (!Detect.IsUserWritable(exe) || !Detect.LooksLikeBadName(exe))
                                {
                                    continue;
                                }
                                Log("Подозрительный автозапуск: " + RunSubKeys[s] + "\\" +
                                    names[i] + " -> " + exe);
                                try
                                {
                                    key.DeleteValue(names[i], false);
                                    Log("Запись автозапуска удалена: " + names[i]);
                                }
                                catch (Exception ex)
                                {
                                    Log("Не удалось удалить запись " + names[i] + ": " + ex.Message);
                                }
                                KillByPath(exe);
                                QuarantineFile(exe, "автозапуск: " + names[i]);
                            }
                        }
                    }
                }
            }
            catch
            {
            }
        }

        private void ScanStartupFolder(string dir)
        {
            try
            {
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir))
                {
                    return;
                }
                foreach (string file in Directory.GetFiles(dir))
                {
                    string target = Detect.ShortcutTarget(file);
                    bool bad = Detect.LooksLikeBadName(file);
                    if (!bad && !string.IsNullOrEmpty(target) && Detect.LooksLikeBadName(target))
                    {
                        bad = true;
                    }
                    if (!bad)
                    {
                        continue;
                    }
                    Log("Подозрительный файл в автозагрузке: " + file +
                        (string.IsNullOrEmpty(target) ? "" : " -> " + target));
                    if (!string.IsNullOrEmpty(target) && File.Exists(target))
                    {
                        KillByPath(target);
                        QuarantineFile(target, "автозагрузка");
                    }
                    QuarantineFile(file, "автозагрузка");
                }
            }
            catch
            {
            }
        }

        private void CleanupPersistence(string exePath, string processName)
        {
            RemoveRunEntries(exePath, processName);
            CleanStartupEntries(exePath, processName);
            CleanScheduledTasks(exePath, processName);
            CleanServices(exePath);
        }

        private void RemoveRunEntries(string exePath, string processName)
        {
            for (int s = 0; s < RunSubKeys.Length; s++)
            {
                RemoveRunEntriesFrom(RegistryHive.CurrentUser, RegistryView.Registry64,
                    RunSubKeys[s], exePath, processName);
                RemoveRunEntriesFrom(RegistryHive.CurrentUser, RegistryView.Registry32,
                    RunSubKeys[s], exePath, processName);
                RemoveRunEntriesFrom(RegistryHive.LocalMachine, RegistryView.Registry64,
                    RunSubKeys[s], exePath, processName);
                RemoveRunEntriesFrom(RegistryHive.LocalMachine, RegistryView.Registry32,
                    RunSubKeys[s], exePath, processName);
            }
        }

        private void RemoveRunEntriesFrom(RegistryHive hive, RegistryView view, string subKey,
            string exePath, string processName)
        {
            try
            {
                using (RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, view))
                using (RegistryKey key = baseKey.OpenSubKey(subKey, true))
                {
                    if (key == null)
                    {
                        return;
                    }
                    string[] names = key.GetValueNames();
                    for (int i = 0; i < names.Length; i++)
                    {
                        string data = key.GetValue(names[i], null,
                            RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                        if (!MatchesEntry(data, exePath, processName))
                        {
                            continue;
                        }
                        try
                        {
                            key.DeleteValue(names[i], false);
                            Log("Удалён автозапуск: " + subKey + "\\" + names[i]);
                        }
                        catch
                        {
                        }
                    }
                }
            }
            catch
            {
            }
        }

        private void CleanStartupEntries(string exePath, string processName)
        {
            string[] dirs =
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
            };
            for (int d = 0; d < dirs.Length; d++)
            {
                try
                {
                    if (string.IsNullOrEmpty(dirs[d]) || !Directory.Exists(dirs[d]))
                    {
                        continue;
                    }
                    foreach (string file in Directory.GetFiles(dirs[d]))
                    {
                        string target = Detect.ShortcutTarget(file);
                        bool match = !string.IsNullOrEmpty(exePath) && !string.IsNullOrEmpty(target) &&
                                     target.IndexOf(exePath, StringComparison.OrdinalIgnoreCase) >= 0;
                        if (!match && !string.IsNullOrEmpty(processName) &&
                            Detect.LooksLikeBadName(processName + ".exe") &&
                            Path.GetFileName(file).IndexOf(processName, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            match = true;
                        }
                        if (!match)
                        {
                            continue;
                        }
                        Log("Удаляю ярлык автозагрузки: " + file);
                        QuarantineFile(file, "ярлык автозагрузки");
                    }
                }
                catch
                {
                }
            }
        }

        private void CleanScheduledTasks(string exePath, string processName)
        {
            try
            {
                string csv = RunTool("schtasks.exe", "/Query /FO CSV /V", 30000);
                if (string.IsNullOrEmpty(csv))
                {
                    return;
                }
                string[] lines = csv.Split(new string[] { "\r\n", "\n" },
                    StringSplitOptions.RemoveEmptyEntries);
                if (lines.Length < 2)
                {
                    return;
                }
                List<string> header = ParseCsv(lines[0]);
                int nameIdx = FindHeader(header, "taskname", "имя задачи");
                int runIdx = FindHeader(header, "task to run", "выполняемая задача");
                if (nameIdx < 0)
                {
                    nameIdx = 1;
                }
                if (runIdx < 0)
                {
                    runIdx = 8;
                }
                int maxIdx = Math.Max(nameIdx, runIdx);
                for (int i = 1; i < lines.Length; i++)
                {
                    List<string> row = ParseCsv(lines[i]);
                    if (row.Count <= maxIdx)
                    {
                        continue;
                    }
                    string task = row[nameIdx].Trim();
                    string run = row[runIdx];
                    if (task.Length == 0 || string.IsNullOrEmpty(run))
                    {
                        continue;
                    }
                    if (task.StartsWith(@"\Microsoft\Windows\", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    if (!MatchesEntry(run, exePath, processName))
                    {
                        continue;
                    }
                    Log("Удаляю задачу планировщика: " + task + " -> " + run);
                    RunTool("schtasks.exe", "/Delete /TN \"" +
                        task.Replace("\"", "") + "\" /F", 15000);
                }
            }
            catch (Exception ex)
            {
                Log("Ошибка проверки задач: " + ex.Message);
            }
        }

        private void CleanServices(string exePath)
        {
            if (string.IsNullOrEmpty(exePath) || Detect.IsProtectedLocation(exePath))
            {
                return;
            }
            try
            {
                using (RegistryKey services = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services"))
                {
                    if (services == null)
                    {
                        return;
                    }
                    string[] names = services.GetSubKeyNames();
                    for (int i = 0; i < names.Length; i++)
                    {
                        try
                        {
                            using (RegistryKey service = services.OpenSubKey(names[i]))
                            {
                                if (service == null)
                                {
                                    continue;
                                }
                                string image = service.GetValue("ImagePath", null,
                                    RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                                if (!MatchesEntry(image, exePath, null))
                                {
                                    continue;
                                }
                                Log("Удаляю службу: " + names[i] + " -> " + image);
                                RunTool("sc.exe", "stop \"" + names[i] + "\"", 10000);
                                RunTool("sc.exe", "delete \"" + names[i] + "\"", 10000);
                            }
                        }
                        catch
                        {
                        }
                    }
                }
            }
            catch
            {
            }
        }

        private void KillByPath(string exePath)
        {
            if (string.IsNullOrEmpty(exePath) || IsOwnPath(exePath))
            {
                return;
            }
            Process[] all = Process.GetProcesses();
            int current = Process.GetCurrentProcess().Id;
            for (int i = 0; i < all.Length; i++)
            {
                Process p = all[i];
                try
                {
                    if (p.Id <= 4 || p.Id == current)
                    {
                        continue;
                    }
                    string path = null;
                    try
                    {
                        path = p.MainModule.FileName;
                    }
                    catch
                    {
                        continue;
                    }
                    if (!string.Equals(path, exePath, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    Log("Останавливаю процесс из автозапуска: " + p.ProcessName + " (" + p.Id + ")");
                    KillTree(p, p.Id);
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

        private static bool MatchesEntry(string data, string exePath, string processName)
        {
            if (string.IsNullOrEmpty(data))
            {
                return false;
            }
            if (!string.IsNullOrEmpty(exePath) &&
                data.IndexOf(exePath, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }
            if (string.IsNullOrEmpty(processName))
            {
                return false;
            }
            string file = processName;
            if (!file.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                file = file + ".exe";
            }
            if (!Detect.LooksLikeBadName(file))
            {
                return false;
            }
            return data.IndexOf("\\" + file, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool IsOwnPath(string path)
        {
            try
            {
                string self = Assembly.GetExecutingAssembly().Location;
                string dir = Path.GetDirectoryName(self);
                return Detect.StartsWithDir(path, dir);
            }
            catch
            {
                return false;
            }
        }

        private static int FindHeader(List<string> header, string a, string b)
        {
            for (int i = 0; i < header.Count; i++)
            {
                string h = header[i].Trim().ToLowerInvariant();
                if (h.Contains(a) || h.Contains(b))
                {
                    return i;
                }
            }
            return -1;
        }

        private static List<string> ParseCsv(string line)
        {
            List<string> result = new List<string>();
            StringBuilder sb = new StringBuilder();
            bool quoted = false;
            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];
                if (quoted)
                {
                    if (c == '"')
                    {
                        if (i + 1 < line.Length && line[i + 1] == '"')
                        {
                            sb.Append('"');
                            i++;
                        }
                        else
                        {
                            quoted = false;
                        }
                    }
                    else
                    {
                        sb.Append(c);
                    }
                }
                else if (c == '"')
                {
                    quoted = true;
                }
                else if (c == ',')
                {
                    result.Add(sb.ToString());
                    sb.Length = 0;
                }
                else
                {
                    sb.Append(c);
                }
            }
            result.Add(sb.ToString());
            return result;
        }
    }
}
