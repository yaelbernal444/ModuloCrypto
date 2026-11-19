using ModuloCrypto.UI.Theme;
using System.ComponentModel;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace ModuloCrypto.UI.Controls;

public enum NeonButtonVariant
{
    Primary,
    Secondary,
    Cyan,
    Success,
    Danger
}

public class NeonButton : Control
{
    private bool _hovered;
    private bool _pressed;

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public NeonButtonVariant Variant { get; set; } = NeonButtonVariant.Primary;

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public int CornerRadius { get; set; } = 10;

    public NeonButton()
    {
        DoubleBuffered = true;
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                 ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        Cursor = Cursors.Hand;
        Size = new Size(160, 40);
        BackColor = HologramTheme.PanelGlass;
        Font = new Font("Segoe UI Semibold", 9.5f, FontStyle.Bold);
        ForeColor = HologramTheme.TextPrimary;
    }

    protected override void OnMouseEnter(EventArgs e) { _hovered = true; Invalidate(); base.OnMouseEnter(e); }
    protected override void OnMouseLeave(EventArgs e) { _hovered = false; _pressed = false; Invalidate(); base.OnMouseLeave(e); }
    protected override void OnMouseDown(MouseEventArgs e) { _pressed = true; Invalidate(); base.OnMouseDown(e); }
    protected override void OnMouseUp(MouseEventArgs e) { _pressed = false; Invalidate(); base.OnMouseUp(e); }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

        Color parentBg = Parent?.BackColor ?? HologramTheme.PanelGlass;
        if (parentBg == Color.Transparent) parentBg = HologramTheme.PanelGlass;
        g.Clear(parentBg);

        var rect = new Rectangle(2, 2, Width - 5, Height - 5);
        if (rect.Width <= 4 || rect.Height <= 4) return;

        (Color c1, Color c2, Color border, Color glow) = Variant switch
        {
            NeonButtonVariant.Cyan => (
                Color.FromArgb(0, 178, 228),
                Color.FromArgb(52, 92, 245),
                HologramTheme.HologramCyan,
                HologramTheme.HologramCyan),
            NeonButtonVariant.Success => (
                Color.FromArgb(36, 185, 100),
                Color.FromArgb(20, 130, 74),
                HologramTheme.Success,
                HologramTheme.Success),
            NeonButtonVariant.Danger => (
                Color.FromArgb(235, 64, 82),
                Color.FromArgb(170, 32, 52),
                HologramTheme.Danger,
                HologramTheme.Danger),
            NeonButtonVariant.Secondary => (
                _hovered ? Color.FromArgb(33, 28, 62) : HologramTheme.PanelGlass,
                _hovered ? Color.FromArgb(26, 22, 50) : HologramTheme.PanelGlass,
                _hovered ? HologramTheme.AccentGlow : HologramTheme.AccentStart,
                HologramTheme.AccentGlow),
            _ => (
                _hovered ? HologramTheme.AccentGlow : HologramTheme.AccentStart,
                _hovered ? HologramTheme.AccentStart : HologramTheme.AccentEnd,
                HologramTheme.AccentGlow,
                HologramTheme.AccentGlow)
        };

        if (!Enabled)
        {
            c1 = Color.FromArgb(32, 28, 48);
            c2 = Color.FromArgb(26, 22, 40);
            border = HologramTheme.BorderSubtle;
        }
        else if (_pressed)
        {
            c1 = ControlPaint.Dark(c1, 0.12f);
            c2 = ControlPaint.Dark(c2, 0.12f);
        }

        using var path = HologramTheme.CreateRoundedPath(rect, CornerRadius);

        if (_hovered && Enabled)
        {
            using var glowPen = new Pen(Color.FromArgb(95, glow), 3f);
            g.DrawPath(glowPen, path);
        }

        using (var brush = new LinearGradientBrush(rect, c1, c2, 135f))
            g.FillPath(brush, path);

        using (var pen = new Pen(Enabled ? border : HologramTheme.BorderSubtle, 1.2f))
            g.DrawPath(pen, path);

        TextRenderer.DrawText(
            g,
            Text,
            Font,
            rect,
            Enabled ? ForeColor : HologramTheme.TextSecondary,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine);
    }
}
