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
        Size = new Size(480, 440);
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
            Location = new Point(32, 26),
            Size = new Size(416, 34),
            BackColor = Color.Transparent
        };

        var lblSub = new Label
        {
            Text = $"Identidad criptográfica en {NodeRuntimeState.CurrentNodeId} (PBKDF2-SHA256 SQLite)",
            Font = new Font("Segoe UI", 9.5f),
            ForeColor = HologramTheme.HologramViolet,
            Location = new Point(32, 60),
            Size = new Size(416, 22),
            BackColor = Color.Transparent
        };

        var lblName = CreateFieldLabel("NOMBRE COMPLETO (EJ. YAEL BERNAL)", 32, 98);
        _txtFullName = new TextBox
        {
            Location = new Point(32, 122),
            Size = new Size(416, 32),
            BackColor = HologramTheme.PanelInput,
            ForeColor = HologramTheme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Segoe UI", 11f),
            PlaceholderText = "Yael Bernal"
        };

        var lblUser = CreateFieldLabel("USUARIO", 32, 168);
        _txtUsername = new TextBox
        {
            Location = new Point(32, 192),
            Size = new Size(416, 32),
            BackColor = HologramTheme.PanelInput,
            ForeColor = HologramTheme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Segoe UI", 11f),
            PlaceholderText = "yael.bernal"
        };

        var lblPass = CreateFieldLabel("CONTRASEÑA", 32, 238);
        _txtPassword = new TextBox
        {
            Location = new Point(32, 262),
            Size = new Size(416, 32),
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
            Location = new Point(32, 304),
            Size = new Size(416, 24),
            BackColor = Color.Transparent
        };

        var btnCreate = new NeonButton
        {
            Text = "Guardar y Acceder",
            Variant = NeonButtonVariant.Primary,
            Location = new Point(32, 336),
            Size = new Size(202, 44),
            Font = new Font("Segoe UI Semibold", 10f, FontStyle.Bold)
        };
        btnCreate.Click += (_, _) => HandleRegister();

        var btnCancel = new NeonButton
        {
            Text = "Cancelar",
            Variant = NeonButtonVariant.Secondary,
            Location = new Point(246, 336),
            Size = new Size(202, 44),
            Font = new Font("Segoe UI Semibold", 10f, FontStyle.Bold)
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
        Font = new Font("Segoe UI Semibold", 8.5f, FontStyle.Bold),
        ForeColor = HologramTheme.HologramViolet,
        Location = new Point(x, y),
        Size = new Size(416, 20),
        BackColor = Color.Transparent
    };

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
