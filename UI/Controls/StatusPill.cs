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
        Width = 172;
        Font = new Font("Segoe UI Semibold", 8.6f);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

        var rect = new Rectangle(1, 1, Width - 3, Height - 3);
        using var path = HologramTheme.CreateRoundedPath(rect, Height / 2);

        using (var bg = new SolidBrush(Color.FromArgb(220, 21, 18, 38)))
            g.FillPath(bg, path);

        using (var pen = new Pen(Color.FromArgb(140, HologramTheme.BorderSubtle), 1f))
            g.DrawPath(pen, path);

        // Glow dot
        int cy = Height / 2;
        using (var glow = new SolidBrush(Color.FromArgb(75, _dotColor)))
            g.FillEllipse(glow, 10, cy - 6, 12, 12);
        using (var dot = new SolidBrush(_dotColor))
            g.FillEllipse(dot, 12, cy - 4, 8, 8);

        var textRect = new Rectangle(26, 0, Width - 32, Height);
        TextRenderer.DrawText(g, Text, Font, textRect, HologramTheme.TextPrimary,
            TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
    }
}
