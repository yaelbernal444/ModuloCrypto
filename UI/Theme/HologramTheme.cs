using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace ModuloCrypto.UI.Theme;

/// <summary>
/// Paleta oficial Lumi AI / Dark Violet Glassmorphism para ModuloCrypto.
/// </summary>
public static class HologramTheme
{
    public static readonly Color BackgroundBase = ColorTranslator.FromHtml("#0B0914");
    public static readonly Color PanelGlass = ColorTranslator.FromHtml("#151226");
    public static readonly Color PanelGlassLight = ColorTranslator.FromHtml("#1D1933");
    public static readonly Color PanelInput = ColorTranslator.FromHtml("#0F0D1D");
    public static readonly Color BorderSubtle = ColorTranslator.FromHtml("#2E284D");

    public static readonly Color AccentStart = ColorTranslator.FromHtml("#6C5CE7");
    public static readonly Color AccentEnd = ColorTranslator.FromHtml("#4834D4");
    public static readonly Color AccentGlow = ColorTranslator.FromHtml("#7D5FFF");

    public static readonly Color HologramCyan = ColorTranslator.FromHtml("#00D2FF");
    public static readonly Color HologramViolet = ColorTranslator.FromHtml("#A29BFE");

    public static readonly Color TextPrimary = ColorTranslator.FromHtml("#F8F9FA");
    public static readonly Color TextSecondary = ColorTranslator.FromHtml("#94A3B8");

    public static readonly Color Danger = ColorTranslator.FromHtml("#FF4757");
    public static readonly Color Success = ColorTranslator.FromHtml("#2ED573");
    public static readonly Color Warning = ColorTranslator.FromHtml("#FFA502");

    public static Font FontTitle(float size = 18f) => new("Segoe UI", size, FontStyle.Bold);
    public static Font FontHeading(float size = 12f) => new("Segoe UI Semibold", size, FontStyle.Bold);
    public static Font FontBody(float size = 9.5f) => new("Segoe UI", size, FontStyle.Regular);
    public static Font FontMono(float size = 9f) => new("Cascadia Mono", size, FontStyle.Regular);

    public static GraphicsPath CreateRoundedPath(Rectangle rect, int radius)
    {
        var path = new GraphicsPath();
        if (radius <= 0)
        {
            path.AddRectangle(rect);
            return path;
        }
        int d = Math.Min(radius * 2, Math.Min(rect.Width, rect.Height));
        if (d <= 0)
        {
            path.AddRectangle(rect);
            return path;
        }
        path.AddArc(rect.X, rect.Y, d, d, 180, 90);
        path.AddArc(rect.Right - d, rect.Y, d, d, 270, 90);
        path.AddArc(rect.Right - d, rect.Bottom - d, d, d, 0, 90);
        path.AddArc(rect.X, rect.Bottom - d, d, d, 90, 90);
        path.CloseFigure();
        return path;
    }

    public static void StyleComboBox(ComboBox cmb, Color? textColor = null)
    {
        Color fg = textColor ?? TextPrimary;
        cmb.DropDownStyle = ComboBoxStyle.DropDownList;
        cmb.FlatStyle = FlatStyle.Flat;
        cmb.BackColor = PanelGlass;
        cmb.ForeColor = fg;
        cmb.DrawMode = DrawMode.OwnerDrawFixed;
        cmb.ItemHeight = 24;
        cmb.DrawItem += (s, e) =>
        {
            if (e.Index < 0) return;
            bool selected = (e.State & DrawItemState.Selected) == DrawItemState.Selected;
            Color bg = selected ? AccentStart : PanelGlass;
            Color itemFg = selected ? Color.White : fg;

            using var bgBrush = new SolidBrush(bg);
            e.Graphics.FillRectangle(bgBrush, e.Bounds);

            string text = cmb.Items[e.Index]?.ToString() ?? string.Empty;
            var textRect = new Rectangle(e.Bounds.X + 6, e.Bounds.Y, e.Bounds.Width - 10, e.Bounds.Height);
            TextRenderer.DrawText(e.Graphics, text, cmb.Font, textRect, itemFg,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine);
        };
    }

    public static void StyleDataGrid(DataGridView grid)
    {
        grid.BackgroundColor = PanelGlass;
        grid.BorderStyle = BorderStyle.None;
        grid.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
        grid.GridColor = BorderSubtle;
        grid.EnableHeadersVisualStyles = false;
        grid.RowHeadersVisible = false;
        grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        grid.MultiSelect = false;
        grid.AllowUserToAddRows = false;
        grid.AllowUserToDeleteRows = false;
        grid.AllowUserToResizeRows = false;
        grid.ReadOnly = true;
        grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
        grid.RowTemplate.Height = 36;

        grid.ColumnHeadersDefaultCellStyle = new DataGridViewCellStyle
        {
            BackColor = PanelGlassLight,
            ForeColor = HologramViolet,
            Font = new Font("Segoe UI Semibold", 9.5f, FontStyle.Bold),
            SelectionBackColor = PanelGlassLight,
            SelectionForeColor = HologramViolet,
            Padding = new Padding(8, 6, 8, 6)
        };
        grid.ColumnHeadersHeight = 40;
        grid.ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.Single;

        grid.DefaultCellStyle = new DataGridViewCellStyle
        {
            BackColor = PanelGlass,
            ForeColor = TextPrimary,
            Font = new Font("Segoe UI", 9.2f),
            SelectionBackColor = Color.FromArgb(65, 53, 128),
            SelectionForeColor = Color.White,
            Padding = new Padding(8, 4, 8, 4)
        };

        grid.AlternatingRowsDefaultCellStyle = new DataGridViewCellStyle
        {
            BackColor = Color.FromArgb(24, 20, 44),
            ForeColor = TextPrimary,
            SelectionBackColor = Color.FromArgb(65, 53, 128),
            SelectionForeColor = Color.White
        };
    }

    public static TextBox CreateDarkTextBox(bool multiline = false, bool readOnly = false, bool mono = false)
    {
        return new TextBox
        {
            BackColor = PanelInput,
            ForeColor = TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            Multiline = multiline,
            ReadOnly = readOnly,
            Font = mono ? FontMono(9f) : FontBody(10f),
            ScrollBars = multiline ? ScrollBars.Vertical : ScrollBars.None
        };
    }

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

    /// <summary>
    /// Aplica barra de título y borde oscuro nativo de Windows 10/11 mediante DwmSetWindowAttribute (#0B0914).
    /// </summary>
    public static void ApplyDarkTitleBar(Form? form)
    {
        if (form == null || form.IsDisposed || !form.IsHandleCreated) return;

        try
        {
            IntPtr hwnd = form.Handle;
            int useDarkMode = 1;
            if (DwmSetWindowAttribute(hwnd, 20, ref useDarkMode, sizeof(int)) != 0)
                _ = DwmSetWindowAttribute(hwnd, 19, ref useDarkMode, sizeof(int));

            int captionColorRef = ToColorRef(BackgroundBase);
            _ = DwmSetWindowAttribute(hwnd, 35, ref captionColorRef, sizeof(int));

            int textColorRef = ToColorRef(TextPrimary);
            _ = DwmSetWindowAttribute(hwnd, 36, ref textColorRef, sizeof(int));

            int borderColorRef = ToColorRef(BorderSubtle);
            _ = DwmSetWindowAttribute(hwnd, 34, ref borderColorRef, sizeof(int));
        }
        catch
        {
        }
    }

    private static int ToColorRef(Color c) => c.R | (c.G << 8) | (c.B << 16);
}
