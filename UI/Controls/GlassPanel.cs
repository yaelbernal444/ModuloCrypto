using ModuloCrypto.UI.Theme;
using System.ComponentModel;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace ModuloCrypto.UI.Controls;

public class GlassPanel : Panel
{
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public int CornerRadius { get; set; } = 16;

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public Color BorderColor { get; set; } = HologramTheme.BorderSubtle;

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public Color FillColorTop { get; set; } = Color.FromArgb(245, 25, 21, 46);

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public Color FillColorBottom { get; set; } = Color.FromArgb(245, 19, 16, 35);

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public bool ShowTopHighlight { get; set; } = true;

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public bool NeonBorderGlow { get; set; }

    public GlassPanel()
    {
        DoubleBuffered = true;
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                 ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        BackColor = Color.Transparent;
        Padding = new Padding(16);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;

        var rect = new Rectangle(1, 1, Width - 3, Height - 3);
        if (rect.Width <= 4 || rect.Height <= 4) return;

        using var path = HologramTheme.CreateRoundedPath(rect, CornerRadius);
        using (var brush = new LinearGradientBrush(rect, FillColorTop, FillColorBottom, 135f))
            g.FillPath(brush, path);

        if (ShowTopHighlight)
        {
            using var hiPen = new Pen(Color.FromArgb(32, 162, 155, 254), 1f);
            g.DrawLine(hiPen, rect.X + CornerRadius, rect.Y + 1, rect.Right - CornerRadius, rect.Y + 1);
        }

        if (NeonBorderGlow)
        {
            using var glowPen = new Pen(Color.FromArgb(65, HologramTheme.AccentGlow), 3f);
            g.DrawPath(glowPen, path);
        }

        using var borderPen = new Pen(BorderColor, 1f);
        g.DrawPath(borderPen, path);
    }
}
