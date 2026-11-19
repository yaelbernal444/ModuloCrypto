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
        Dock = DockStyle.Top;
        Font = new Font("Segoe UI Semibold", 10f);
    }

    protected override void OnMouseEnter(EventArgs e) { _hovered = true; Invalidate(); base.OnMouseEnter(e); }
    protected override void OnMouseLeave(EventArgs e) { _hovered = false; Invalidate(); base.OnMouseLeave(e); }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

        var rect = new Rectangle(10, 3, Width - 20, Height - 6);
        if (rect.Width <= 4 || rect.Height <= 4) return;

        using var path = HologramTheme.CreateRoundedPath(rect, 11);

        if (_active)
        {
            using var brush = new LinearGradientBrush(rect,
                Color.FromArgb(220, HologramTheme.AccentStart),
                Color.FromArgb(215, HologramTheme.AccentEnd), 0f);
            g.FillPath(brush, path);

            using var pen = new Pen(Color.FromArgb(140, HologramTheme.AccentGlow), 1f);
            g.DrawPath(pen, path);

            // Indicador lateral neón cian
            using var barBrush = new SolidBrush(HologramTheme.HologramCyan);
            g.FillRectangle(barBrush, rect.X + 4, rect.Y + 9, 3, rect.Height - 18);
        }
        else if (_hovered)
        {
            using var brush = new SolidBrush(Color.FromArgb(32, 125, 95, 255));
            g.FillPath(brush, path);
        }

        Color fg = _active ? Color.White : (_hovered ? HologramTheme.TextPrimary : HologramTheme.TextSecondary);
        Color glyphColor = _active ? HologramTheme.HologramCyan : fg;

        var iconRect = new Rectangle(rect.X + 14, rect.Y, 26, rect.Height);
        TextRenderer.DrawText(g, IconGlyph, new Font("Segoe UI Symbol", 11.5f), iconRect, glyphColor,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);

        int textRightMargin = _badgeCount > 0 ? 48 : 10;
        var textRect = new Rectangle(rect.X + 44, rect.Y, rect.Width - 44 - textRightMargin, rect.Height);
        TextRenderer.DrawText(g, Text, Font, textRect, fg,
            TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);

        if (_badgeCount > 0)
        {
            string badgeText = _badgeCount > 99 ? "99+" : _badgeCount.ToString();
            var badgeRect = new Rectangle(rect.Right - 36, rect.Y + (rect.Height - 22) / 2, 28, 22);
            using var badgePath = HologramTheme.CreateRoundedPath(badgeRect, 10);
            using var badgeBrush = new LinearGradientBrush(badgeRect, HologramTheme.HologramCyan, HologramTheme.AccentStart, 45f);
            g.FillPath(badgeBrush, badgePath);
            TextRenderer.DrawText(g, badgeText, new Font("Segoe UI", 8.5f, FontStyle.Bold), badgeRect, Color.White,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        }
    }
}
