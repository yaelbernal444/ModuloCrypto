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
    public int CornerRadius { get; set; } = 11;

    public NeonButton()
    {
        DoubleBuffered = true;
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                 ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        Cursor = Cursors.Hand;
        Size = new Size(150, 40);
        Font = new Font("Segoe UI Semibold", 9.8f, FontStyle.Bold);
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

        var rect = new Rectangle(2, 2, Width - 5, Height - 5);
        if (rect.Width <= 4 || rect.Height <= 4) return;

        (Color c1, Color c2, Color border, Color glow) = Variant switch
        {
            NeonButtonVariant.Cyan => (
                Color.FromArgb(0, 180, 230),
                Color.FromArgb(56, 97, 251),
                HologramTheme.HologramCyan,
                HologramTheme.HologramCyan),
            NeonButtonVariant.Success => (
                Color.FromArgb(34, 180, 96),
                Color.FromArgb(20, 128, 72),
                HologramTheme.Success,
                HologramTheme.Success),
            NeonButtonVariant.Danger => (
                Color.FromArgb(235, 64, 82),
                Color.FromArgb(170, 32, 52),
                HologramTheme.Danger,
                HologramTheme.Danger),
            NeonButtonVariant.Secondary => (
                _hovered ? Color.FromArgb(42, 36, 74) : Color.FromArgb(28, 24, 52),
                _hovered ? Color.FromArgb(30, 25, 58) : Color.FromArgb(20, 17, 38),
                _hovered ? HologramTheme.AccentGlow : HologramTheme.BorderSubtle,
                HologramTheme.AccentGlow),
            _ => (
                HologramTheme.AccentStart,
                HologramTheme.AccentEnd,
                HologramTheme.AccentGlow,
                HologramTheme.AccentGlow)
        };

        if (!Enabled)
        {
            c1 = Color.FromArgb(35, 32, 52);
            c2 = Color.FromArgb(28, 25, 44);
            border = HologramTheme.BorderSubtle;
        }
        else if (_pressed)
        {
            c1 = ControlPaint.Dark(c1, 0.12f);
            c2 = ControlPaint.Dark(c2, 0.12f);
        }
        else if (_hovered && Variant != NeonButtonVariant.Secondary)
        {
            c1 = ControlPaint.Light(c1, 0.12f);
        }

        using var path = HologramTheme.CreateRoundedPath(rect, CornerRadius);

        if (_hovered && Enabled)
        {
            using var glowPen = new Pen(Color.FromArgb(95, glow), 3.5f);
            g.DrawPath(glowPen, path);
        }

        using (var brush = new LinearGradientBrush(rect, c1, c2, 135f))
            g.FillPath(brush, path);

        using (var pen = new Pen(Enabled ? border : HologramTheme.BorderSubtle, 1f))
            g.DrawPath(pen, path);

        TextRenderer.DrawText(
            g,
            Text,
            Font,
            rect,
            Enabled ? ForeColor : HologramTheme.TextSecondary,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
    }
}
