using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using ModuloCrypto.UI.Controls;
using ModuloCrypto.UI.Theme;
using System.Drawing;
using System.Windows.Forms;

namespace ModuloCrypto.UI.Forms;

/// <summary>
/// Modal oscuro glassmorphism para registrar un nuevo integrante con NombreCompleto, Usuario y Contraseña.
/// </summary>
public sealed class FormRegisterModal : Form
{
    public Usuario? RegisteredUser { get; private set; }

    private readonly TextBox _txtFullName;
    private readonly TextBox _txtUsername;
    private readonly TextBox _txtPassword;
    private readonly Label _lblStatus;

    public FormRegisterModal()
    {
        Text = "Registrar Nuevo Integrante — ModuloCrypto";
        FormBorderStyle = FormBorderStyle.None;
        StartPosition = FormStartPosition.CenterParent;
        Size = new Size(510, 460);
        BackColor = HologramTheme.BackgroundBase;
        ForeColor = HologramTheme.TextPrimary;
        DoubleBuffered = true;
        KeyPreview = true;

        var card = new GlassPanel
        {
            Dock = DockStyle.Fill,
            CornerRadius = 18,
            NeonBorderGlow = true,
            BorderColor = HologramTheme.AccentStart,
            FillColorTop = HologramTheme.PanelGlass,
            FillColorBottom = Color.FromArgb(16, 13, 30),
            Padding = new Padding(32)
        };

        var lblTitle = new Label
        {
            Text = "Registrar Nuevo Integrante",
            Font = new Font("Segoe UI", 16f, FontStyle.Bold),
            ForeColor = HologramTheme.TextPrimary,
            Location = new Point(32, 24),
            Size = new Size(446, 36),
            BackColor = Color.Transparent
        };

        var lblSub = new Label
        {
            Text = $"Identidad criptográfica en {NodeRuntimeState.CurrentNodeId} (PBKDF2-SHA256 SQLite)",
            Font = new Font("Segoe UI", 9.5f),
            ForeColor = HologramTheme.HologramViolet,
            Location = new Point(32, 60),
            Size = new Size(446, 24),
            BackColor = Color.Transparent
        };

        var lblName = CreateFieldLabel("NOMBRE COMPLETO (EJ. YAEL BERNAL)", 32, 96);
        _txtFullName = new TextBox
        {
            Location = new Point(32, 122),
            Size = new Size(446, 32),
            BackColor = HologramTheme.PanelInput,
            ForeColor = HologramTheme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Segoe UI", 11f),
            PlaceholderText = "Yael Bernal"
        };

        var lblUser = CreateFieldLabel("USUARIO", 32, 168);
        _txtUsername = new TextBox
        {
            Location = new Point(32, 194),
            Size = new Size(446, 32),
            BackColor = HologramTheme.PanelInput,
            ForeColor = HologramTheme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Segoe UI", 11f),
            PlaceholderText = "yael.bernal"
        };

        var lblPass = CreateFieldLabel("CONTRASEÑA", 32, 240);
        _txtPassword = new TextBox
        {
            Location = new Point(32, 266),
            Size = new Size(446, 32),
            BackColor = HologramTheme.PanelInput,
            ForeColor = HologramTheme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Segoe UI", 11f),
            UseSystemPasswordChar = true
        };

        _lblStatus = new Label
        {
            Text = "",
            Font = new Font("Segoe UI", 9f),
            ForeColor = HologramTheme.Danger,
            Location = new Point(32, 308),
            Size = new Size(446, 34),
            BackColor = Color.Transparent
        };

        var btnCreate = new NeonButton
        {
            Text = "Guardar y Acceder",
            Variant = NeonButtonVariant.Primary,
            AutoFitWidth = false,
            Location = new Point(32, 354),
            Size = new Size(216, 46),
            Font = new Font("Segoe UI", 9.6f, FontStyle.Bold)
        };
        btnCreate.Click += (_, _) => HandleRegister();

        var btnCancel = new NeonButton
        {
            Text = "Cancelar",
            Variant = NeonButtonVariant.Secondary,
            AutoFitWidth = false,
            Location = new Point(262, 354),
            Size = new Size(216, 46),
            Font = new Font("Segoe UI", 9.6f, FontStyle.Bold)
        };
        btnCancel.Click += (_, _) =>
        {
            DialogResult = DialogResult.Cancel;
            Close();
        };

        card.Controls.AddRange(new Control[]
        {
            lblTitle, lblSub,
            lblName, _txtFullName,
            lblUser, _txtUsername,
            lblPass, _txtPassword,
            _lblStatus,
            btnCreate, btnCancel
        });

        Controls.Add(card);

        KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.Enter)
            {
                e.SuppressKeyPress = true;
                HandleRegister();
            }
            else if (e.KeyCode == Keys.Escape)
            {
                DialogResult = DialogResult.Cancel;
                Close();
            }
        };
    }

    private static Label CreateFieldLabel(string text, int x, int y) => new()
    {
        Text = text,
        Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
        ForeColor = HologramTheme.HologramViolet,
        Location = new Point(x, y),
        Size = new Size(446, 22),
        BackColor = Color.Transparent
    };

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        HologramTheme.ApplyDarkTitleBar(this);
    }

    private void HandleRegister()
    {
        var (success, message, user) = AuthService.Register(
            _txtFullName.Text,
            _txtUsername.Text,
            _txtPassword.Text,
            NodeRuntimeState.CurrentNodeId,
            $"Operador {NodeRuntimeState.CurrentNodeId}");

        if (!success || user == null)
        {
            _lblStatus.ForeColor = HologramTheme.Danger;
            _lblStatus.Text = message;
            return;
        }

        RegisteredUser = user;
        DialogResult = DialogResult.OK;
        Close();
    }
}
