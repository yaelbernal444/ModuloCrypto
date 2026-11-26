using ModuloCrypto.UI.Theme;
using System.ComponentModel;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace ModuloCrypto.UI.Controls;

public class SidebarNavButton : Control
{
    private bool _hovered;
    private bool _active;
    private int _badgeCount;
    private readonly Font _iconFont = new("Segoe UI Symbol", 11f);
    private readonly Font _badgeFont = new("Segoe UI", 8f, FontStyle.Bold);

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public string IconGlyph { get; set; } = "◆";

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public string NavKey { get; set; } = string.Empty;

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public bool IsActive
    {
        get => _active;
        set { _active = value; Invalidate(); }
    }

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public int BadgeCount
    {
        get => _badgeCount;
        set { _badgeCount = Math.Max(0, value); Invalidate(); }
    }

    public SidebarNavButton()
    {
        DoubleBuffered = true;
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                 ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        Cursor = Cursors.Hand;
        Height = 46;
        Width = 250;
        BackColor = HologramTheme.PanelGlass;
        Font = new Font("Segoe UI", 9.8f, FontStyle.Bold);
    }

    protected override void OnMouseEnter(EventArgs e) { _hovered = true; Invalidate(); base.OnMouseEnter(e); }
    protected override void OnMouseLeave(EventArgs e) { _hovered = false; Invalidate(); base.OnMouseLeave(e); }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

        g.Clear(HologramTheme.PanelGlass);

        var rect = new Rectangle(2, 1, Width - 5, Height - 3);
        if (rect.Width <= 4 || rect.Height <= 4) return;

        using var path = HologramTheme.CreateRoundedPath(rect, 10);

        if (_active)
        {
            using var brush = new LinearGradientBrush(rect,
                HologramTheme.AccentStart,
                HologramTheme.AccentEnd, 0f);
            g.FillPath(brush, path);

            using var pen = new Pen(HologramTheme.AccentGlow, 1f);
            g.DrawPath(pen, path);

            using var barBrush = new SolidBrush(HologramTheme.HologramCyan);
            g.FillRectangle(barBrush, rect.X + 4, rect.Y + 9, 3, rect.Height - 18);
        }
        else if (_hovered)
        {
            using var brush = new SolidBrush(Color.FromArgb(40, 125, 95, 255));
            g.FillPath(brush, path);
            using var pen = new Pen(HologramTheme.BorderSubtle, 1f);
            g.DrawPath(pen, path);
        }

        Color fg = _active ? Color.White : (_hovered ? HologramTheme.TextPrimary : HologramTheme.TextSecondary);
        Color glyphColor = _active ? HologramTheme.HologramCyan : fg;

        var iconRect = new Rectangle(rect.X + 10, rect.Y, 24, rect.Height);
        TextRenderer.DrawText(g, IconGlyph, _iconFont, iconRect, glyphColor,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix);

        int textRightMargin = _badgeCount > 0 ? 44 : 10;
        var textRect = new Rectangle(rect.X + 36, rect.Y, rect.Width - 36 - textRightMargin, rect.Height);
        TextRenderer.DrawText(g, Text, Font, textRect, fg,
            TextFormatFlags.Left | TextFormatFlags.VerticalCenter |
            TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);

        if (_badgeCount > 0)
        {
            string badgeText = _badgeCount > 99 ? "99+" : _badgeCount.ToString();
            var badgeRect = new Rectangle(rect.Right - 36, rect.Y + (rect.Height - 20) / 2, 28, 20);
            using var badgePath = HologramTheme.CreateRoundedPath(badgeRect, 9);
            using var badgeBrush = new LinearGradientBrush(badgeRect, HologramTheme.HologramCyan, HologramTheme.AccentStart, 45f);
            g.FillPath(badgeBrush, badgePath);
            TextRenderer.DrawText(g, badgeText, _badgeFont, badgeRect, Color.White,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _iconFont.Dispose();
            _badgeFont.Dispose();
        }
        base.Dispose(disposing);
    }
}
