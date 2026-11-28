using ModuloCrypto.UI.Theme;
using System.Drawing;
using System.Windows.Forms;

namespace ModuloCrypto.UI.Controls;

public enum HologramDialogType
{
    Info,
    Success,
    Warning,
    Error,
    Question
}

public enum HologramDialogButtons
{
    OK,
    YesNo,
    YesNoCancel
}

/// <summary>
/// Diálogo modal sin bordes siguiendo exactamente la estética Dark Violet Glassmorphism de HologramTheme.
/// Reemplaza al 100 % las ventanas nativas MessageBox.Show con soporte de scroll, copia de texto y botones NeonButton.
/// </summary>
public sealed class HologramDialog : Form
{
    private readonly TextBox _txtBody;
    private readonly NeonButton _primaryButton;
    private readonly Font _iconFont = new("Segoe UI", 12.5f, FontStyle.Bold);
    private readonly Font _titleFont = new("Segoe UI", 11.2f, FontStyle.Bold);
    private readonly Font _closeFont = new("Segoe UI", 10.5f, FontStyle.Bold);
    private readonly Font _bodyFont;

    private bool _dragging;
    private Point _dragCursorStart;
    private Point _dragFormStart;

    public HologramDialog(
        HologramDialogType dialogType,
        string message,
        string title,
        HologramDialogButtons buttons)
    {
        string safeTitle = string.IsNullOrWhiteSpace(title) ? "ModuloCrypto" : title.Trim();
        string normalizedMsg = (message ?? string.Empty)
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace("\r", "\n", StringComparison.Ordinal)
            .Replace("\n", Environment.NewLine, StringComparison.Ordinal);

        bool looksReport = normalizedMsg.Contains('╔') ||
                           normalizedMsg.Contains("•") ||
                           normalizedMsg.Contains("->") ||
                           normalizedMsg.Contains("SHA-256") ||
                           normalizedMsg.Split(Environment.NewLine).Length > 7;
        _bodyFont = looksReport ? new Font("Cascadia Mono", 9.1f) : new Font("Segoe UI", 9.8f);

        Text = safeTitle;
        FormBorderStyle = FormBorderStyle.None;
        StartPosition = FormStartPosition.CenterParent;
        ShowInTaskbar = false;
        MinimizeBox = false;
        MaximizeBox = false;
        AutoScaleMode = AutoScaleMode.Dpi;
        DoubleBuffered = true;
        KeyPreview = true;
        BackColor = HologramTheme.BackgroundBase;
        ForeColor = HologramTheme.TextPrimary;
        Padding = new Padding(1);

        (Color accentColor, string glyphText) = dialogType switch
        {
            HologramDialogType.Success => (HologramTheme.Success, "✓"),
            HologramDialogType.Warning => (HologramTheme.Warning, "⚠"),
            HologramDialogType.Error => (HologramTheme.Danger, "✕"),
            HologramDialogType.Question => (HologramTheme.HologramCyan, "?"),
            _ => (HologramTheme.HologramCyan, "ⓘ")
        };

        var card = new GlassPanel
        {
            Dock = DockStyle.Fill,
            CornerRadius = 16,
            NeonBorderGlow = true,
            BorderColor = accentColor,
            FillColorTop = HologramTheme.PanelGlass,
            FillColorBottom = Color.FromArgb(16, 13, 30),
            Padding = new Padding(20, 14, 20, 16)
        };

        // Barra superior arrastrable
        var topBar = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = 42,
            ColumnCount = 3,
            RowCount = 1,
            BackColor = Color.Transparent,
            Margin = new Padding(0, 0, 0, 8)
        };
        topBar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 34));
        topBar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
        topBar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 34));

        var lblIcon = new Label
        {
            Text = glyphText,
            Font = _iconFont,
            ForeColor = accentColor,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleCenter,
            BackColor = Color.Transparent
        };

        var lblTitle = new Label
        {
            Text = safeTitle,
            Font = _titleFont,
            ForeColor = HologramTheme.TextPrimary,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            AutoEllipsis = true,
            BackColor = Color.Transparent
        };

        var btnClose = new Button
        {
            Text = "✕",
            Font = _closeFont,
            ForeColor = HologramTheme.TextSecondary,
            BackColor = Color.Transparent,
            FlatStyle = FlatStyle.Flat,
            Dock = DockStyle.Fill,
            Cursor = Cursors.Hand,
            TabStop = false
        };
        btnClose.FlatAppearance.BorderSize = 0;
        btnClose.FlatAppearance.MouseOverBackColor = Color.FromArgb(48, 255, 71, 87);
        btnClose.FlatAppearance.MouseDownBackColor = Color.FromArgb(80, 255, 71, 87);
        btnClose.MouseEnter += (_, _) => btnClose.ForeColor = HologramTheme.Danger;
        btnClose.MouseLeave += (_, _) => btnClose.ForeColor = HologramTheme.TextSecondary;
        btnClose.Click += (_, _) =>
        {
            DialogResult = buttons == HologramDialogButtons.YesNoCancel
                ? DialogResult.Cancel
                : (buttons == HologramDialogButtons.YesNo ? DialogResult.No : DialogResult.OK);
            Close();
        };

        void WireDrag(Control c)
        {
            c.MouseDown += (_, e) =>
            {
                if (e.Button != MouseButtons.Left) return;
                _dragging = true;
                _dragCursorStart = Cursor.Position;
                _dragFormStart = Location;
            };
            c.MouseMove += (_, _) =>
            {
                if (!_dragging) return;
                Point diff = new(Cursor.Position.X - _dragCursorStart.X, Cursor.Position.Y - _dragCursorStart.Y);
                Location = new Point(_dragFormStart.X + diff.X, _dragFormStart.Y + diff.Y);
            };
            c.MouseUp += (_, _) => _dragging = false;
        }
        WireDrag(topBar);
        WireDrag(lblIcon);
        WireDrag(lblTitle);

        topBar.Controls.Add(lblIcon, 0, 0);
        topBar.Controls.Add(lblTitle, 1, 0);
        topBar.Controls.Add(btnClose, 2, 0);

        // Cuerpo oscuro seleccionable con scroll vertical automático
        var bodyWrap = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = HologramTheme.PanelInput,
            Padding = new Padding(12, 10, 12, 10)
        };
        bodyWrap.Paint += (_, e) =>
        {
            using var pen = new Pen(HologramTheme.BorderSubtle, 1f);
            e.Graphics.DrawRectangle(pen, 0, 0, bodyWrap.Width - 1, bodyWrap.Height - 1);
        };

        _txtBody = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            BorderStyle = BorderStyle.None,
            BackColor = HologramTheme.PanelInput,
            ForeColor = HologramTheme.TextPrimary,
            Font = _bodyFont,
            ScrollBars = ScrollBars.Vertical,
            WordWrap = true,
            TabStop = false,
            Text = normalizedMsg
        };
        bodyWrap.Controls.Add(_txtBody);

        // Barra inferior de botones NeonButton
        var btnBar = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            Height = 52,
            FlowDirection = FlowDirection.RightToLeft,
            WrapContents = false,
            Padding = new Padding(0, 12, 0, 0),
            BackColor = Color.Transparent
        };

        if (buttons == HologramDialogButtons.OK)
        {
            _primaryButton = new NeonButton
            {
                Text = "Aceptar",
                Variant = dialogType switch
                {
                    HologramDialogType.Success => NeonButtonVariant.Success,
                    HologramDialogType.Error => NeonButtonVariant.Danger,
                    HologramDialogType.Warning => NeonButtonVariant.Primary,
                    _ => NeonButtonVariant.Cyan
                },
                Margin = new Padding(0)
            };
            _primaryButton.FitToText(minWidth: 118, height: 36);
            _primaryButton.Click += (_, _) => { DialogResult = DialogResult.OK; Close(); };
            btnBar.Controls.Add(_primaryButton);
        }
        else
        {
            if (buttons == HologramDialogButtons.YesNoCancel)
            {
                var btnCancel = new NeonButton
                {
                    Text = "Cancelar",
                    Variant = NeonButtonVariant.Secondary,
                    Margin = new Padding(8, 0, 0, 0)
                };
                btnCancel.FitToText(minWidth: 108, height: 36);
                btnCancel.Click += (_, _) => { DialogResult = DialogResult.Cancel; Close(); };
                btnBar.Controls.Add(btnCancel);
            }

            var btnNo = new NeonButton
            {
                Text = "No",
                Variant = NeonButtonVariant.Secondary,
                Margin = new Padding(8, 0, 0, 0)
            };
            btnNo.FitToText(minWidth: 96, height: 36);
            btnNo.Click += (_, _) => { DialogResult = DialogResult.No; Close(); };
            btnBar.Controls.Add(btnNo);

            _primaryButton = new NeonButton
            {
                Text = "Sí",
                Variant = NeonButtonVariant.Success,
                Margin = new Padding(0)
            };
            _primaryButton.FitToText(minWidth: 96, height: 36);
            _primaryButton.Click += (_, _) => { DialogResult = DialogResult.Yes; Close(); };
            btnBar.Controls.Add(_primaryButton);
        }

        card.Controls.Add(bodyWrap);
        card.Controls.Add(btnBar);
        card.Controls.Add(topBar);
        Controls.Add(card);

        // Tamaño dinámico acotado para caber holgado en 1366x768 @ 150% DPI
        Size measured = TextRenderer.MeasureText(
            string.IsNullOrEmpty(normalizedMsg) ? " " : normalizedMsg,
            _bodyFont,
            new Size(660, 0),
            TextFormatFlags.WordBreak | TextFormatFlags.TextBoxControl);

        int desiredW = Math.Clamp(measured.Width + 110, 480, 740);
        int desiredH = Math.Clamp(measured.Height + 175, 225, 520);
        Size = new Size(desiredW, desiredH);

        Shown += (_, _) =>
        {
            _txtBody.SelectionStart = 0;
            _txtBody.SelectionLength = 0;
            _primaryButton.Focus();
        };

        KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.Enter)
            {
                e.SuppressKeyPress = true;
                DialogResult = buttons == HologramDialogButtons.OK ? DialogResult.OK : DialogResult.Yes;
                Close();
            }
            else if (e.KeyCode == Keys.Escape)
            {
                DialogResult = buttons == HologramDialogButtons.YesNoCancel
                    ? DialogResult.Cancel
                    : (buttons == HologramDialogButtons.YesNo ? DialogResult.No : DialogResult.OK);
                Close();
            }
        };
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        HologramTheme.ApplyDarkTitleBar(this);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _iconFont.Dispose();
            _titleFont.Dispose();
            _closeFont.Dispose();
            _bodyFont.Dispose();
        }
        base.Dispose(disposing);
    }

    public static void ShowInfo(IWin32Window? owner, string message, string title = "ModuloCrypto") =>
        ShowInternal(owner, HologramDialogType.Info, message, title, HologramDialogButtons.OK);

    public static void ShowSuccess(IWin32Window? owner, string message, string title = "ModuloCrypto") =>
        ShowInternal(owner, HologramDialogType.Success, message, title, HologramDialogButtons.OK);

    public static void ShowWarning(IWin32Window? owner, string message, string title = "ModuloCrypto") =>
        ShowInternal(owner, HologramDialogType.Warning, message, title, HologramDialogButtons.OK);

    public static void ShowError(IWin32Window? owner, string message, string title = "ModuloCrypto") =>
        ShowInternal(owner, HologramDialogType.Error, message, title, HologramDialogButtons.OK);

    public static DialogResult ShowQuestion(
        IWin32Window? owner,
        string message,
        string title,
        bool includeCancel = false,
        HologramDialogType iconType = HologramDialogType.Question) =>
        ShowInternal(
            owner,
            iconType,
            message,
            title,
            includeCancel ? HologramDialogButtons.YesNoCancel : HologramDialogButtons.YesNo);

    private static DialogResult ShowInternal(
        IWin32Window? owner,
        HologramDialogType dialogType,
        string message,
        string title,
        HologramDialogButtons buttons)
    {
        using var dlg = new HologramDialog(dialogType, message, title, buttons);
        if (owner == null)
        {
            dlg.StartPosition = FormStartPosition.CenterScreen;
            return dlg.ShowDialog();
        }
        return dlg.ShowDialog(owner);
    }
}
