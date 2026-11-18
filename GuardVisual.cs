using System;
using System.Drawing;
using System.Drawing.Imaging;

namespace WinLockerGuard
{
    /// <summary>
    /// Смотрит на сам экран, а не на текст окон: пранки вроде «Вас заметили»
    /// рисуют глаз и надпись картинкой, поэтому GetWindowText их не видит.
    /// </summary>
    internal static class GuardVisual
    {
        internal static bool IsMostlyDark(IntPtr hwnd, Native.RECT r)
        {
            int w = r.Right - r.Left;
            int h = r.Bottom - r.Top;
            if (w < 320 || h < 200)
            {
                return false;
            }
            Bitmap bmp = null;
            try
            {
                bmp = new Bitmap(w, h, PixelFormat.Format24bppRgb);
                using (Graphics g = Graphics.FromImage(bmp))
                {
                    g.CopyFromScreen(r.Left, r.Top, 0, 0, new Size(w, h),
                        CopyPixelOperation.SourceCopy);
                }

                int total = 0;
                int dark = 0;
                long sum = 0;
                int stepX = Math.Max(1, w / 48);
                int stepY = Math.Max(1, h / 27);
                for (int y = stepY / 2; y < h; y += stepY)
                {
                    for (int x = stepX / 2; x < w; x += stepX)
                    {
                        Color c = bmp.GetPixel(x, y);
                        int lum = (c.R * 299 + c.G * 587 + c.B * 114) / 1000;
                        sum += lum;
                        total++;
                        if (lum < 40)
                        {
                            dark++;
                        }
                    }
                }
                if (total < 50)
                {
                    return false;
                }
                double ratio = (double)dark / total;
                double avg = (double)sum / total;
                return ratio >= 0.55 && avg < 65;
            }
            catch
            {
                return false;
            }
            finally
            {
                if (bmp != null)
                {
                    bmp.Dispose();
                }
            }
        }
    }
}
