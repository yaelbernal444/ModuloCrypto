using ModuloCrypto.UI.Theme;
using System.ComponentModel;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace ModuloCrypto.UI.Controls;

public class StatusPill : Control
{
    private bool _isActive = true;
    private Color _dotColor = HologramTheme.Success;

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public int MinimumWidth { get; set; } = 135;

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public bool IsActive
    {
        get => _isActive;
        set
        {
            _isActive = value;
            _dotColor = value ? HologramTheme.Success : HologramTheme.Danger;
            Invalidate();
        }
    }

    public StatusPill()
    {
        DoubleBuffered = true;
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                 ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        Height = 32;
        Width = 180;
        BackColor = HologramTheme.PanelGlass;
        Font = new Font("Segoe UI", 8.8f, FontStyle.Bold);
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        AutoAdjustWidth();
    }

    protected override void OnTextChanged(EventArgs e)
    {
        base.OnTextChanged(e);
        AutoAdjustWidth();
        Invalidate();
    }

    protected override void OnFontChanged(EventArgs e)
    {
        base.OnFontChanged(e);
        AutoAdjustWidth();
        Invalidate();
    }

    public void AutoAdjustWidth()
    {
        if (string.IsNullOrEmpty(Text)) return;
        Size measured = TextRenderer.MeasureText(
            Text,
            Font,
            Size.Empty,
            TextFormatFlags.SingleLine | TextFormatFlags.NoPrefix);
        Width = Math.Max(MinimumWidth, measured.Width + 44);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

        Color parentBg = Parent?.BackColor ?? HologramTheme.BackgroundBase;
        if (parentBg == Color.Transparent) parentBg = HologramTheme.BackgroundBase;
        g.Clear(parentBg);

        var rect = new Rectangle(1, 1, Width - 3, Height - 3);
        using var path = HologramTheme.CreateRoundedPath(rect, Height / 2);

        using (var bg = new SolidBrush(HologramTheme.PanelGlass))
            g.FillPath(bg, path);

        using (var pen = new Pen(HologramTheme.BorderSubtle, 1f))
            g.DrawPath(pen, path);

        int cy = Height / 2;
        using (var glow = new SolidBrush(Color.FromArgb(75, _dotColor)))
            g.FillEllipse(glow, 10, cy - 6, 12, 12);
        using (var dot = new SolidBrush(_dotColor))
            g.FillEllipse(dot, 12, cy - 4, 8, 8);

        var textRect = new Rectangle(28, 0, Width - 36, Height);
        TextRenderer.DrawText(
            g,
            Text,
            Font,
            textRect,
            HologramTheme.TextPrimary,
            TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.NoPrefix);
    }
}
