using System.Drawing;
using System.Drawing.Drawing2D;
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

    public static Font FontTitle(float size = 18f) => new("Segoe UI Semibold", size, FontStyle.Bold);
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
}
