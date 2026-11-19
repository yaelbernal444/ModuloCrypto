using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using ModuloCrypto.UI.Controls;
using ModuloCrypto.UI.Theme;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace ModuloCrypto.UI.Forms;

public sealed class FormLogin : Form
{
    public Usuario? AuthenticatedUser { get; private set; }

    private readonly GlassPanel _mainCard;
    private readonly HologramLockControl _previewHologram;
    private readonly TextBox _txtUsername;
    private readonly TextBox _txtPassword;
    private readonly ComboBox _cmbNode;
    private readonly ComboBox _cmbRole;
    private readonly Label _lblNode;
    private readonly Label _lblRole;
    private readonly Label _lblModeTitle;
    private readonly Label _lblFeedback;
    private readonly NeonButton _btnSubmit;
    private readonly NeonButton _btnToggleMode;
    private bool _isRegisterMode;

    public FormLogin()
    {
        Text = "ModuloCrypto — Acceso al Nodo Criptográfico";
        WindowState = FormWindowState.Maximized;
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(1024, 680);
        BackColor = HologramTheme.BackgroundBase;
        ForeColor = HologramTheme.TextPrimary;
        DoubleBuffered = true;
        KeyPreview = true;

        _mainCard = new GlassPanel
        {
            Size = new Size(960, 580),
            CornerRadius = 22,
            NeonBorderGlow = true,
            BorderColor = Color.FromArgb(95, HologramTheme.AccentGlow),
            Padding = new Padding(0)
        };
        Controls.Add(_mainCard);

        // Panel Izquierdo: Identidad Visual + Holograma Binario en Vivo
        var leftPanel = new Panel
        {
            Dock = DockStyle.Left,
            Width = 465,
            BackColor = Color.FromArgb(14, 11, 27),
            Padding = new Padding(26)
        };

        var lblBrand = new Label
        {
            Text = "◆ ModuloCrypto",
            Font = new Font("Segoe UI", 22f, FontStyle.Bold),
            ForeColor = HologramTheme.TextPrimary,
            Dock = DockStyle.Top,
            Height = 46
        };

        var lblTagline = new Label
        {
            Text = "RED DISTRIBUIDA DE 8 NODOS • ENRUTAMIENTO TIPO TOR (.ZIP)\nAPI REST :5000  •  SQLITE LOCAL  •  21 ALGORITMOS OFICIALES",
            Font = new Font("Segoe UI Semibold", 8.4f),
            ForeColor = HologramTheme.HologramViolet,
            Dock = DockStyle.Top,
            Height = 42
        };

        _previewHologram = new HologramLockControl
        {
            Dock = DockStyle.Fill,
            ActiveAlgorithmLabel = "X.509",
            StatusSubtitle = "Sistema Criptográfico Holográfico • Listo"
        };

        var statusBar = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            Height = 42,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            BackColor = Color.Transparent,
            Padding = new Padding(0, 6, 0, 0)
        };
        statusBar.Controls.Add(new StatusPill
        {
            Text = NodeRuntimeState.ApiOnline ? $"API: Online :{NodeRuntimeState.ApiPort}" : "API: Offline",
            IsActive = NodeRuntimeState.ApiOnline,
            Width = 148
        });
        statusBar.Controls.Add(new StatusPill
        {
            Text = NodeRuntimeState.SqliteConnected ? "SQLite: OK" : "SQLite: Error",
            IsActive = NodeRuntimeState.SqliteConnected,
            Width = 120
        });
        statusBar.Controls.Add(new StatusPill
        {
            Text = NodeRuntimeState.CertificateActive ? "X.509: Activo" : "X.509: Off",
            IsActive = NodeRuntimeState.CertificateActive,
            Width = 132
        });

        leftPanel.Controls.Add(_previewHologram);
        leftPanel.Controls.Add(statusBar);
        leftPanel.Controls.Add(lblTagline);
        leftPanel.Controls.Add(lblBrand);

        // Panel Derecho: Formulario Glassmorphism Login / Registro
        var rightPanel = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.Transparent,
            Padding = new Padding(44, 38, 44, 30)
        };

        _lblModeTitle = new Label
        {
            Text = "Iniciar Sesión en el Nodo",
            Font = new Font("Segoe UI", 19f, FontStyle.Bold),
            ForeColor = HologramTheme.TextPrimary,
            Location = new Point(44, 38),
            Size = new Size(410, 38)
        };

        var lblSub = new Label
        {
            Text = "Autenticación SHA-256 sobre ModuloCrypto.db (SQLite)",
            Font = HologramTheme.FontBody(9.5f),
            ForeColor = HologramTheme.TextSecondary,
            Location = new Point(44, 78),
            Size = new Size(410, 24)
        };

        var lblUser = CreateFieldLabel("USUARIO DEL OPERADOR", 44, 122);
        _txtUsername = new TextBox
        {
            Location = new Point(44, 146),
            Size = new Size(405, 34),
            BackColor = HologramTheme.PanelInput,
            ForeColor = HologramTheme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Segoe UI", 11.5f),
            Text = "admin"
        };

        var lblPass = CreateFieldLabel("CONTRASEÑA", 44, 196);
        _txtPassword = new TextBox
        {
            Location = new Point(44, 220),
            Size = new Size(405, 34),
            BackColor = HologramTheme.PanelInput,
            ForeColor = HologramTheme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Segoe UI", 11.5f),
            UseSystemPasswordChar = true,
            Text = "admin123"
        };

        _lblNode = CreateFieldLabel("NODO ASIGNADO (RED DE 8 NODOS)", 44, 268);
        _cmbNode = new ComboBox
        {
            Location = new Point(44, 292),
            Size = new Size(195, 32),
            DropDownStyle = ComboBoxStyle.DropDownList,
            BackColor = HologramTheme.PanelInput,
            ForeColor = HologramTheme.TextPrimary,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI Semibold", 10f)
        };
        for (int i = 1; i <= 8; i++) _cmbNode.Items.Add($"NODO-0{i}");
        _cmbNode.SelectedItem = "NODO-04";

        _lblRole = CreateFieldLabel("ROL DEL OPERADOR", 254, 268);
        _cmbRole = new ComboBox
        {
            Location = new Point(254, 292),
            Size = new Size(195, 32),
            DropDownStyle = ComboBoxStyle.DropDownList,
            BackColor = HologramTheme.PanelInput,
            ForeColor = HologramTheme.TextPrimary,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI Semibold", 10f)
        };
        _cmbRole.Items.AddRange(new object[] { "Operador Tor", "Arquitecto Seguridad", "Auditor Cripto" });
        _cmbRole.SelectedIndex = 0;

        _lblFeedback = new Label
        {
            Text = "Demo preconfigurada: admin / admin123  (NODO-04)",
            Font = new Font("Segoe UI", 9f),
            ForeColor = HologramTheme.HologramCyan,
            Location = new Point(44, 344),
            Size = new Size(405, 42)
        };

        _btnSubmit = new NeonButton
        {
            Text = "ACCEDER AL DASHBOARD  →",
            Variant = NeonButtonVariant.Primary,
            Location = new Point(44, 404),
            Size = new Size(405, 46),
            Font = new Font("Segoe UI Semibold", 10.5f, FontStyle.Bold)
        };
        _btnSubmit.Click += (_, _) => HandleSubmit();

        _btnToggleMode = new NeonButton
        {
            Text = "¿Nuevo integrante? Registrar Operador",
            Variant = NeonButtonVariant.Secondary,
            Location = new Point(44, 462),
            Size = new Size(405, 40),
            Font = new Font("Segoe UI Semibold", 9.5f)
        };
        _btnToggleMode.Click += (_, _) => ToggleMode();

        var btnExit = new NeonButton
        {
            Text = "Salir",
            Variant = NeonButtonVariant.Danger,
            Location = new Point(349, 516),
            Size = new Size(100, 34),
            Font = new Font("Segoe UI Semibold", 9f)
        };
        btnExit.Click += (_, _) => { DialogResult = DialogResult.Cancel; Close(); };

        rightPanel.Controls.AddRange(new Control[]
        {
            _lblModeTitle, lblSub, lblUser, _txtUsername, lblPass, _txtPassword,
            _lblNode, _cmbNode, _lblRole, _cmbRole, _lblFeedback,
            _btnSubmit, _btnToggleMode, btnExit
        });

        _mainCard.Controls.Add(rightPanel);
        _mainCard.Controls.Add(leftPanel);

        ApplyModeVisibility();
        CenterCard();

        Resize += (_, _) => CenterCard();
        KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.Enter)
            {
                e.SuppressKeyPress = true;
                HandleSubmit();
            }
        };
    }

    private static Label CreateFieldLabel(string text, int x, int y) => new()
    {
        Text = text,
        Font = new Font("Segoe UI Semibold", 8.2f, FontStyle.Bold),
        ForeColor = HologramTheme.HologramViolet,
        Location = new Point(x, y),
        Size = new Size(260, 20)
    };

    private void CenterCard()
    {
        _mainCard.Location = new Point(
            Math.Max(16, (ClientSize.Width - _mainCard.Width) / 2),
            Math.Max(16, (ClientSize.Height - _mainCard.Height) / 2));
    }

    private void ToggleMode()
    {
        _isRegisterMode = !_isRegisterMode;
        ApplyModeVisibility();
    }

    private void ApplyModeVisibility()
    {
        _lblNode.Visible = _isRegisterMode;
        _cmbNode.Visible = _isRegisterMode;
        _lblRole.Visible = _isRegisterMode;
        _cmbRole.Visible = _isRegisterMode;

        if (_isRegisterMode)
        {
            _lblModeTitle.Text = "Registrar Nuevo Operador";
            _btnSubmit.Text = "CREAR CUENTA Y ACCEDER  →";
            _btnToggleMode.Text = "Ya tengo cuenta • Volver a Iniciar Sesión";
            _txtUsername.Text = "";
            _txtPassword.Text = "";
            _lblFeedback.ForeColor = HologramTheme.TextSecondary;
            _lblFeedback.Text = "El perfil se almacenará con contraseña SHA-256 en ModuloCrypto.db.";
            _previewHologram.TriggerDecryptAnimation("SHA256");
        }
        else
        {
            _lblModeTitle.Text = "Iniciar Sesión en el Nodo";
            _btnSubmit.Text = "ACCEDER AL DASHBOARD  →";
            _btnToggleMode.Text = "¿Nuevo integrante? Registrar Operador";
            _lblFeedback.ForeColor = HologramTheme.HologramCyan;
            _lblFeedback.Text = "Demo preconfigurada: admin / admin123  (NODO-04)";
            _previewHologram.SetIdle("Sistema Criptográfico Holográfico • Listo");
        }
    }

    private void HandleSubmit()
    {
        string user = _txtUsername.Text.Trim();
        string pass = _txtPassword.Text;

        if (_isRegisterMode)
        {
            string nodo = _cmbNode.SelectedItem?.ToString() ?? "NODO-04";
            string rol = _cmbRole.SelectedItem?.ToString() ?? "Operador Tor";
            var res = AuthService.Register(user, pass, nodo, rol);
            if (!res.Success || res.User == null)
            {
                _lblFeedback.ForeColor = HologramTheme.Danger;
                _lblFeedback.Text = res.Message;
                return;
            }
            AuthenticatedUser = res.User;
        }
        else
        {
            var auth = AuthService.Authenticate(user, pass);
            if (auth == null)
            {
                _lblFeedback.ForeColor = HologramTheme.Danger;
                _lblFeedback.Text = "Credenciales inválidas. Verifica usuario y contraseña.";
                _previewHologram.TriggerEncryptAnimation("DENIED");
                return;
            }
            AuthenticatedUser = auth;
        }

        NodeRuntimeState.CurrentNodeId = AuthenticatedUser.NodoAsignado;
        DialogResult = DialogResult.OK;
        Close();
    }

    protected override void OnPaintBackground(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;

        using var bg = new LinearGradientBrush(
            ClientRectangle,
            ColorTranslator.FromHtml("#07050E"),
            ColorTranslator.FromHtml("#120D24"),
            135f);
        g.FillRectangle(bg, ClientRectangle);

        // Sutil cuadrícula espacial futurista
        using var gridPen = new Pen(Color.FromArgb(14, 162, 155, 254), 1f);
        for (int x = 0; x < Width; x += 48) g.DrawLine(gridPen, x, 0, x, Height);
        for (int y = 0; y < Height; y += 48) g.DrawLine(gridPen, 0, y, Width, y);

        // Resplandor ambiental superior izquierda (violeta) e inferior derecha (cian)
        DrawGlowOrb(g, Width * 0.16f, Height * 0.22f, 320, Color.FromArgb(38, HologramTheme.AccentStart));
        DrawGlowOrb(g, Width * 0.84f, Height * 0.78f, 360, Color.FromArgb(30, HologramTheme.HologramCyan));
    }

    private static void DrawGlowOrb(Graphics g, float cx, float cy, float radius, Color color)
    {
        var rect = new RectangleF(cx - radius, cy - radius, radius * 2, radius * 2);
        using var path = new GraphicsPath();
        path.AddEllipse(rect);
        using var pgb = new PathGradientBrush(path)
        {
            CenterColor = color,
            SurroundColors = new[] { Color.Transparent }
        };
        g.FillEllipse(pgb, rect);
    }
}
