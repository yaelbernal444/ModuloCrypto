using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using ModuloCrypto.UI.Controls;
using ModuloCrypto.UI.Theme;
using System.ComponentModel;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.Windows.Forms;

namespace ModuloCrypto.UI.Forms;

public sealed class FormLogin : Form
{
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public Usuario? AuthenticatedUser { get; private set; }

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public ProtocolVersionMode SelectedProtocolVersion { get; private set; } = ProtocolVersionMode.V2;

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public int SelectedTeamNumber { get; private set; } = 1;

    private const string CryptoGlyphPool = "0123456789ABCDEF@#$%&*<>+=?∑∆Ω";

    private sealed class CascadeDrop
    {
        public float X;
        public float Y;
        public float Speed;
        public int Length;
        public char[] Chars = Array.Empty<char>();
    }

    private readonly System.Windows.Forms.Timer _cascadeTimer;
    private readonly List<CascadeDrop> _drops = new();
    private readonly Random _rng = new(1337);
    private readonly Font _cascadeFont = new("Consolas", 11f, FontStyle.Bold);
    private float _scanlineY;
    private int _lastColumnsWidth;

    private readonly GlassPanel _mainCard;
    private readonly HologramLockControl _previewHologram;
    private readonly TextBox _txtUsername;
    private readonly TextBox _txtPassword;
    private readonly ComboBox _cmbProtocolVersion;
    private readonly Label _lblTeamCaption;
    private readonly ComboBox _cmbTeamNumber;
    private readonly Label _lblFeedback;

    public FormLogin(ProtocolVersionMode initialVersion = ProtocolVersionMode.V2, int initialTeam = 1)
    {
        SelectedProtocolVersion = initialVersion;
        SelectedTeamNumber = Math.Clamp(initialTeam, 1, 99);

        Text = "ModuloCrypto — Inicio de Sesión (Arquitectura Dual v1.0 / v2.0)";
        WindowState = FormWindowState.Maximized;
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(1060, 720);
        BackColor = HologramTheme.BackgroundBase;
        ForeColor = HologramTheme.TextPrimary;
        DoubleBuffered = true;
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                 ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        KeyPreview = true;

        _mainCard = new GlassPanel
        {
            Size = new Size(960, 600),
            CornerRadius = 22,
            NeonBorderGlow = true,
            BorderColor = Color.FromArgb(115, HologramTheme.AccentGlow),
            FillColorTop = HologramTheme.PanelGlass,
            FillColorBottom = Color.FromArgb(16, 13, 30),
            Padding = new Padding(2)
        };
        Controls.Add(_mainCard);

        // Panel Izquierdo: Identidad Visual + Holograma Binario en Vivo
        var leftPanel = new Panel
        {
            Dock = DockStyle.Left,
            Width = 455,
            BackColor = Color.FromArgb(15, 12, 28),
            Padding = new Padding(28, 26, 24, 24)
        };

        var lblBrand = new Label
        {
            Text = "ModuloCrypto",
            Font = new Font("Segoe UI", 20f, FontStyle.Bold),
            ForeColor = HologramTheme.TextPrimary,
            Dock = DockStyle.Top,
            Height = 48,
            AutoEllipsis = false,
            TextAlign = ContentAlignment.MiddleLeft
        };

        var lblTagline = new Label
        {
            Text = "RED DISTRIBUIDA DE 8 NODOS",
            Font = new Font("Segoe UI", 10f, FontStyle.Bold),
            ForeColor = HologramTheme.HologramViolet,
            Dock = DockStyle.Top,
            Height = 30,
            AutoEllipsis = false,
            TextAlign = ContentAlignment.MiddleLeft
        };

        _previewHologram = new HologramLockControl
        {
            Dock = DockStyle.Fill,
            ActiveAlgorithmLabel = "EQ01",
            StatusSubtitle = "Núcleo Criptográfico Holográfico • Listo"
        };

        leftPanel.Controls.Add(_previewHologram);
        leftPanel.Controls.Add(lblTagline);
        leftPanel.Controls.Add(lblBrand);

        // Panel Derecho: Formulario Limpio con Selector de Versión (v1.0 / v2.0) + Equipo (1..99)
        var rightPanel = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = HologramTheme.PanelGlass,
            Padding = new Padding(44, 34, 44, 30)
        };

        var lblTitle = new Label
        {
            Text = "Iniciar Sesión",
            Font = new Font("Segoe UI", 20f, FontStyle.Bold),
            ForeColor = HologramTheme.TextPrimary,
            Location = new Point(44, 30),
            Size = new Size(415, 44),
            AutoEllipsis = false
        };

        var lblSub = new Label
        {
            Text = "Acceso al Nodo Criptográfico",
            Font = new Font("Segoe UI", 10.5f, FontStyle.Regular),
            ForeColor = HologramTheme.TextSecondary,
            Location = new Point(44, 76),
            Size = new Size(415, 26),
            AutoEllipsis = false
        };

        var lblUser = CreateFieldLabel("USUARIO", 44, 118, 415);
        _txtUsername = new TextBox
        {
            Location = new Point(44, 144),
            Size = new Size(415, 34),
            BackColor = HologramTheme.PanelInput,
            ForeColor = HologramTheme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Segoe UI", 11.5f),
            Text = "",
            PlaceholderText = "Ingresa tu usuario"
        };

        var lblPass = CreateFieldLabel("CONTRASEÑA", 44, 192, 415);
        _txtPassword = new TextBox
        {
            Location = new Point(44, 218),
            Size = new Size(415, 34),
            BackColor = HologramTheme.PanelInput,
            ForeColor = HologramTheme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Segoe UI", 11.5f),
            UseSystemPasswordChar = true,
            Text = "",
            PlaceholderText = "Ingresa tu contraseña"
        };

        var lblProto = CreateFieldLabel("VERSIÓN DE PROTOCOLO", 44, 268, 300);
        _cmbProtocolVersion = new ComboBox
        {
            Location = new Point(44, 294),
            Size = new Size(305, 34),
            Font = new Font("Segoe UI", 9.2f, FontStyle.Bold)
        };
        HologramTheme.StyleComboBox(_cmbProtocolVersion, HologramTheme.HologramCyan);
        _cmbProtocolVersion.Items.Add("Versión 1.0 — Legado ModuloCrypto (NODO-01 • :5000)");
        _cmbProtocolVersion.Items.Add("Versión 2.0 — Estándar Interoperable (EQ01 • :5001 + UDP 5099)");

        _lblTeamCaption = CreateFieldLabel("EQUIPO", 359, 268, 100);
        _cmbTeamNumber = new ComboBox
        {
            Location = new Point(359, 294),
            Size = new Size(100, 34),
            Font = new Font("Cascadia Mono", 9.2f, FontStyle.Bold)
        };
        HologramTheme.StyleComboBox(_cmbTeamNumber, HologramTheme.HologramViolet);
        for (int t = 1; t <= 99; t++)
        {
            _cmbTeamNumber.Items.Add($"EQ{t:D2}");
        }
        _cmbTeamNumber.SelectedIndex = SelectedTeamNumber - 1;
        _cmbProtocolVersion.SelectedIndex = SelectedProtocolVersion == ProtocolVersionMode.V1 ? 0 : 1;

        _cmbProtocolVersion.SelectedIndexChanged += (_, _) => SyncProtocolSelectionUi();
        _cmbTeamNumber.SelectedIndexChanged += (_, _) => SyncProtocolSelectionUi();

        _lblFeedback = new Label
        {
            Text = "",
            Font = new Font("Segoe UI", 9.2f),
            ForeColor = HologramTheme.Danger,
            Location = new Point(44, 340),
            Size = new Size(415, 36)
        };

        var btnLogin = new NeonButton
        {
            Text = "Iniciar Sesión",
            Variant = NeonButtonVariant.Primary,
            AutoFitWidth = false,
            Location = new Point(44, 386),
            Size = new Size(415, 48),
            Font = new Font("Segoe UI", 10.2f, FontStyle.Bold)
        };
        btnLogin.Click += (_, _) => HandleLogin();

        var btnRegister = new NeonButton
        {
            Text = "Registrar Nuevo Integrante",
            Variant = NeonButtonVariant.Secondary,
            AutoFitWidth = false,
            Location = new Point(44, 448),
            Size = new Size(415, 46),
            Font = new Font("Segoe UI", 9.8f, FontStyle.Bold)
        };
        btnRegister.Click += (_, _) => OpenRegisterModal();

        var lblIpPreview = new Label
        {
            Text = $"IP Local Detectada: {NodeRuntimeState.LocalIpAddress} ({NodeRuntimeState.ActiveInterfaceName})",
            Font = new Font("Cascadia Mono", 8.5f, FontStyle.Bold),
            ForeColor = HologramTheme.HologramCyan,
            Location = new Point(44, 514),
            Size = new Size(415, 24),
            TextAlign = ContentAlignment.MiddleCenter
        };

        rightPanel.Controls.AddRange(new Control[]
        {
            lblTitle, lblSub,
            lblUser, _txtUsername,
            lblPass, _txtPassword,
            lblProto, _cmbProtocolVersion,
            _lblTeamCaption, _cmbTeamNumber,
            _lblFeedback,
            btnLogin, btnRegister,
            lblIpPreview
        });

        _mainCard.Controls.Add(rightPanel);
        _mainCard.Controls.Add(leftPanel);

        SyncProtocolSelectionUi();
        CenterCard();

        _cascadeTimer = new System.Windows.Forms.Timer { Interval = 50 };
        _cascadeTimer.Tick += OnCascadeTick;
        _cascadeTimer.Start();

        Resize += (_, _) =>
        {
            CenterCard();
            EnsureCascadeColumns();
        };

        KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.Enter)
            {
                e.SuppressKeyPress = true;
                HandleLogin();
            }
        };
    }

    private void SyncProtocolSelectionUi()
    {
        bool isV2 = _cmbProtocolVersion.SelectedIndex == 1;
        SelectedProtocolVersion = isV2 ? ProtocolVersionMode.V2 : ProtocolVersionMode.V1;
        SelectedTeamNumber = Math.Clamp(_cmbTeamNumber.SelectedIndex + 1, 1, 99);

        _lblTeamCaption.Visible = isV2;
        _cmbTeamNumber.Visible = isV2;
        _cmbProtocolVersion.Width = isV2 ? 305 : 415;

        if (isV2)
        {
            string eqId = $"EQ{SelectedTeamNumber:D2}";
            int port = 5000 + SelectedTeamNumber;
            _previewHologram.ActiveAlgorithmLabel = eqId;
            _previewHologram.StatusSubtitle = $"Estándar v2.0 • {eqId} (:{port} + UDP 5099)";
        }
        else
        {
            _previewHologram.ActiveAlgorithmLabel = "NODO-01";
            _previewHologram.StatusSubtitle = "Versión 1.0 Legado • NODO-01 (:5000)";
        }
    }

    private static Label CreateFieldLabel(string text, int x, int y, int width) => new()
    {
        Text = text,
        Font = new Font("Segoe UI", 8.8f, FontStyle.Bold),
        ForeColor = HologramTheme.HologramViolet,
        Location = new Point(x, y),
        Size = new Size(width, 24)
    };

    private void CenterCard()
    {
        _mainCard.Location = new Point(
            Math.Max(16, (ClientSize.Width - _mainCard.Width) / 2),
            Math.Max(16, (ClientSize.Height - _mainCard.Height) / 2));
    }

    private void EnsureCascadeColumns()
    {
        int w = Math.Max(1280, ClientSize.Width);
        int h = Math.Max(720, ClientSize.Height);
        if (Math.Abs(w - _lastColumnsWidth) < 32 && _drops.Count > 0) return;

        _lastColumnsWidth = w;
        _drops.Clear();
        const int colStep = 26;
        int cols = w / colStep;

        for (int i = 0; i < cols; i++)
        {
            int len = _rng.Next(8, 19);
            var chars = new char[len];
            for (int c = 0; c < len; c++)
                chars[c] = CryptoGlyphPool[_rng.Next(CryptoGlyphPool.Length)];

            _drops.Add(new CascadeDrop
            {
                X = i * colStep + 6,
                Y = -_rng.Next(0, h),
                Speed = _rng.Next(10, 24),
                Length = len,
                Chars = chars
            });
        }
    }

    private void OnCascadeTick(object? sender, EventArgs e)
    {
        EnsureCascadeColumns();
        int h = Math.Max(720, ClientSize.Height);

        foreach (var drop in _drops)
        {
            drop.Y += drop.Speed;
            if (drop.Chars.Length > 0)
            {
                int mutateIdx = _rng.Next(drop.Chars.Length);
                drop.Chars[mutateIdx] = CryptoGlyphPool[_rng.Next(CryptoGlyphPool.Length)];
            }

            if (drop.Y - drop.Length * 18 > h)
            {
                drop.Y = -_rng.Next(20, 260);
                drop.Speed = _rng.Next(10, 24);
            }
        }

        _scanlineY += 9f;
        if (_scanlineY > h) _scanlineY = 0f;

        Invalidate();
    }

    private void HandleLogin()
    {
        SyncProtocolSelectionUi();
        string user = _txtUsername.Text.Trim();
        string pass = _txtPassword.Text;

        var auth = AuthService.Authenticate(user, pass);
        if (auth == null)
        {
            _lblFeedback.ForeColor = HologramTheme.Danger;
            _lblFeedback.Text = "Credenciales inválidas. Verifica usuario y contraseña.";
            _previewHologram.TriggerEncryptAnimation("DENIED");
            return;
        }

        AuthenticatedUser = auth;
        DialogResult = DialogResult.OK;
        Close();
    }

    private void OpenRegisterModal()
    {
        SyncProtocolSelectionUi();
        NodeRuntimeState.ConfigureForMode(SelectedProtocolVersion, SelectedTeamNumber);

        using var modal = new FormRegisterModal();
        if (modal.ShowDialog(this) == DialogResult.OK && modal.RegisteredUser != null)
        {
            AuthenticatedUser = modal.RegisteredUser;
            DialogResult = DialogResult.OK;
            Close();
        }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;

        g.Clear(HologramTheme.BackgroundBase);

        EnsureCascadeColumns();
        const float charStepY = 18f;

        foreach (var drop in _drops)
        {
            for (int i = 0; i < drop.Length; i++)
            {
                float cy = drop.Y - i * charStepY;
                if (cy < -20 || cy > Height + 20) continue;

                Color color;
                if (i == 0)
                {
                    color = Color.FromArgb(235, HologramTheme.HologramCyan);
                }
                else
                {
                    float fade = 1f - (i / (float)drop.Length);
                    int alpha = (int)Math.Clamp(fade * 165f, 18f, 165f);
                    Color baseTrail = i < 3 ? HologramTheme.AccentGlow : HologramTheme.AccentStart;
                    color = Color.FromArgb(alpha, baseTrail);
                }

                using var brush = new SolidBrush(color);
                g.DrawString(drop.Chars[i].ToString(), _cascadeFont, brush, drop.X, cy);
            }
        }

        if (Width > 0)
        {
            var scanRect = new RectangleF(0, _scanlineY - 18f, Width, 36f);
            using (var scanBrush = new LinearGradientBrush(
                scanRect,
                Color.FromArgb(0, HologramTheme.AccentGlow),
                Color.FromArgb(45, HologramTheme.HologramCyan),
                90f))
            {
                g.FillRectangle(scanBrush, scanRect);
            }

            using var linePen = new Pen(Color.FromArgb(115, HologramTheme.HologramCyan), 1.2f);
            g.DrawLine(linePen, 0, _scanlineY, Width, _scanlineY);
        }
    }

    protected override void OnPaintBackground(PaintEventArgs e)
    {
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _cascadeTimer.Stop();
            _cascadeTimer.Dispose();
            _cascadeFont.Dispose();
        }
        base.Dispose(disposing);
    }
}
