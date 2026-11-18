using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;
using Microsoft.Win32;

namespace WinLockerGuard
{
    internal static class Native
    {
        internal delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [StructLayout(LayoutKind.Sequential)]
        internal struct RECT
        {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }

        internal const int GWL_EXSTYLE = -20;
        internal const int WS_EX_TOPMOST = 0x00000008;
        internal const uint GW_OWNER = 4;
        internal const int MOVEFILE_DELAY_UNTIL_REBOOT = 4;

        [DllImport("user32.dll")]
        internal static extern bool EnumWindows(EnumWindowsProc callback, IntPtr lParam);

        [DllImport("user32.dll")]
        internal static extern bool EnumChildWindows(IntPtr parent, EnumWindowsProc callback, IntPtr lParam);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        internal static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int maxCount);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        internal static extern int GetWindowTextLength(IntPtr hWnd);

        [DllImport("user32.dll")]
        internal static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll")]
        internal static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);

        [DllImport("user32.dll")]
        internal static extern IntPtr GetWindow(IntPtr hWnd, uint cmd);

        [DllImport("user32.dll")]
        internal static extern int GetWindowLong(IntPtr hWnd, int index);

        [DllImport("user32.dll")]
        internal static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);

        [DllImport("user32.dll")]
        internal static extern bool BlockInput(bool block);

        [DllImport("user32.dll")]
        internal static extern bool ClipCursor(IntPtr rect);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool MoveFileEx(string existing, string next, int flags);
    }

    internal static class Detect
    {
        private static readonly string[] StrongPhrases =
        {
            "ваш компьютер заблокирован",
            "компьютер заблокирован",
            "windows заблокирован",
            "your computer has been locked",
            "your computer is locked",
            "your files have been encrypted",
            "все ваши файлы зашифрованы",
            "ваши файлы зашифрованы",
            "для разблокировки",
            "to unlock your computer",
            "вас заметили",
            "тебя заметили",
            "я тебя вижу",
            "я вижу тебя",
            "слежу за тобой",
            "you have been noticed",
            "i can see you"
        };

        private static readonly string[] LockWords =
        {
            "заблокирован", "заблокирова", "блокировк", "locked", "lock screen"
        };

        private static readonly string[] AuthorityWords =
        {
            "полици", "мвд", "фсб", "прокуратур", "police", "government", "fbi", "фбр"
        };

        private static readonly string[] MoneyWords =
        {
            "выкуп", "ransom", "bitcoin", "биткоин", "qiwi", "киви", "webmoney",
            "payeer", "перевед", "оплат", "payment"
        };

        private static readonly string[] SmsWords =
        {
            "sms", "смс", "код разблок", "unlock code", "activation code", "код активации"
        };

        private static readonly string[] FileWords =
        {
            "зашифрован", "encrypted", "ваши файлы", "your files"
        };

        private static readonly string[] BadNameParts =
        {
            "winlock", "win-lock", "locker", "ransom", "cryptolocker", "cryptor",
            "keylog", "smslock", "police", "trojan", "blocker",
            "заметили", "тебя заметил", "слежк", "прикол", "noticed", "prank"
        };

        internal static bool LooksLikeLocker(string text, out bool veryStrong)
        {
            veryStrong = false;
            if (string.IsNullOrEmpty(text))
            {
                return false;
            }
            string s = " " + text.ToLowerInvariant()
                .Replace('\r', ' ').Replace('\n', ' ').Replace('\t', ' ') + " ";
            for (int i = 0; i < StrongPhrases.Length; i++)
            {
                if (s.Contains(StrongPhrases[i]))
                {
                    veryStrong = true;
                    return true;
                }
            }
            int groups = 0;
            if (ContainsAny(s, LockWords)) groups++;
            if (ContainsAny(s, AuthorityWords)) groups++;
            if (ContainsAny(s, MoneyWords)) groups++;
            if (ContainsAny(s, SmsWords)) groups++;
            if (ContainsAny(s, FileWords)) groups++;
            return groups >= 2;
        }

        private static bool ContainsAny(string text, string[] words)
        {
            for (int i = 0; i < words.Length; i++)
            {
                if (text.Contains(words[i]))
                {
                    return true;
                }
            }
            return false;
        }

        internal static bool LooksLikeBadName(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return false;
            }
            string n = Path.GetFileNameWithoutExtension(path).ToLowerInvariant();
            if (n.Length == 0)
            {
                return false;
            }
            if (n.Contains("winlockerguard") || n.Contains("adblock") ||
                n.Contains("antivirus") || n.Contains("virusscan"))
            {
                return false;
            }
            for (int i = 0; i < BadNameParts.Length; i++)
            {
                if (n.Contains(BadNameParts[i]))
                {
                    return true;
                }
            }
            return false;
        }

        internal static string CollectWindowText(IntPtr hwnd)
        {
            StringBuilder sb = new StringBuilder(4096);
            AppendText(hwnd, sb);
            Native.EnumChildWindows(hwnd, delegate(IntPtr child, IntPtr lparam)
            {
                if (sb.Length > 6000)
                {
                    return false;
                }
                AppendText(child, sb);
                return true;
            }, IntPtr.Zero);
            return sb.ToString();
        }

        private static void AppendText(IntPtr hwnd, StringBuilder sb)
        {
            try
            {
                int len = Native.GetWindowTextLength(hwnd);
                if (len <= 0)
                {
                    return;
                }
                StringBuilder b = new StringBuilder(len + 2);
                Native.GetWindowText(hwnd, b, b.Capacity);
                if (b.Length > 0)
                {
                    sb.Append(b);
                    sb.Append(' ');
                }
            }
            catch
            {
            }
        }

        internal static bool IsFullscreen(IntPtr hwnd, Native.RECT r)
        {
            try
            {
                Rectangle b = Screen.FromHandle(hwnd).Bounds;
                const int tol = 16;
                return r.Left <= b.Left + tol &&
                       r.Top <= b.Top + tol &&
                       r.Right >= b.Right - tol &&
                       r.Bottom >= b.Bottom - tol;
            }
            catch
            {
                return false;
            }
        }

        internal static bool IsTopmost(IntPtr hwnd)
        {
            try
            {
                return (Native.GetWindowLong(hwnd, Native.GWL_EXSTYLE) & Native.WS_EX_TOPMOST) != 0;
            }
            catch
            {
                return false;
            }
        }

        internal static bool IsProtectedLocation(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return false;
            }
            try
            {
                string full = Path.GetFullPath(path);
                string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                string pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
                return StartsWithDir(full, win) || StartsWithDir(full, pf) || StartsWithDir(full, pf86);
            }
            catch
            {
                return true;
            }
        }

        internal static bool IsUserWritable(string path)
        {
            if (IsProtectedLocation(path))
            {
                return false;
            }
            return StartsWithDir(path, Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)) ||
                   StartsWithDir(path, Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)) ||
                   StartsWithDir(path, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)) ||
                   StartsWithDir(path, Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)) ||
                   StartsWithDir(path, Path.GetTempPath());
        }

        internal static bool StartsWithDir(string path, string dir)
        {
            if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(dir))
            {
                return false;
            }
            try
            {
                string p = Path.GetFullPath(path).TrimEnd('\\');
                string d = Path.GetFullPath(dir).TrimEnd('\\');
                return p.Equals(d, StringComparison.OrdinalIgnoreCase) ||
                       p.StartsWith(d + "\\", StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        internal static string ExtractExecutable(string command)
        {
            if (string.IsNullOrEmpty(command))
            {
                return null;
            }
            string s;
            try
            {
                s = Environment.ExpandEnvironmentVariables(command.Trim());
            }
            catch
            {
                s = command.Trim();
            }
            if (s.Length == 0)
            {
                return null;
            }
            if (s[0] == '"')
            {
                int end = s.IndexOf('"', 1);
                if (end > 1)
                {
                    return s.Substring(1, end - 1);
                }
            }
            string[] exts = { ".exe", ".scr", ".com", ".bat", ".cmd", ".vbs", ".js", ".ps1" };
            int best = -1;
            for (int i = 0; i < exts.Length; i++)
            {
                int idx = s.IndexOf(exts[i], StringComparison.OrdinalIgnoreCase);
                if (idx >= 0)
                {
                    int end = idx + exts[i].Length;
                    if (best < 0 || end < best)
                    {
                        best = end;
                    }
                }
            }
            if (best > 0)
            {
                return s.Substring(0, best).Trim().Trim('"');
            }
            return null;
        }

        internal static string ShortcutTarget(string link)
        {
            object shell = null;
            object shortcut = null;
            try
            {
                Type t = Type.GetTypeFromProgID("WScript.Shell");
                if (t == null)
                {
                    return null;
                }
                shell = Activator.CreateInstance(t);
                dynamic shellDynamic = shell;
                shortcut = shellDynamic.CreateShortcut(link);
                dynamic shortcutDynamic = shortcut;
                string target = shortcutDynamic.TargetPath as string;
                return target;
            }
            catch
            {
                return null;
            }
            finally
            {
                if (shortcut != null)
                {
                    try { Marshal.FinalReleaseComObject(shortcut); } catch { }
                }
                if (shell != null)
                {
                    try { Marshal.FinalReleaseComObject(shell); } catch { }
                }
            }
        }
    }
}
