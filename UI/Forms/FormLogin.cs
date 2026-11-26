using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using ModuloCrypto.UI.Controls;
using ModuloCrypto.UI.Theme;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.Windows.Forms;

namespace ModuloCrypto.UI.Forms;

public sealed class FormLogin : Form
{
    public Usuario? AuthenticatedUser { get; private set; }

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
    private readonly Label _lblFeedback;

    public FormLogin()
    {
        Text = $"ModuloCrypto — {NodeRuntimeState.CurrentNodeId} (Estándar v2.0)";
        WindowState = FormWindowState.Maximized;
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(1024, 680);
        BackColor = HologramTheme.BackgroundBase;
        ForeColor = HologramTheme.TextPrimary;
        DoubleBuffered = true;
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                 ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        KeyPreview = true;

        _mainCard = new GlassPanel
        {
            Size = new Size(940, 540),
            CornerRadius = 22,
            NeonBorderGlow = true,
            BorderColor = Color.FromArgb(115, HologramTheme.AccentGlow),
            FillColorTop = HologramTheme.PanelGlass,
            FillColorBottom = Color.FromArgb(16, 13, 30),
            Padding = new Padding(2)
        };
        Controls.Add(_mainCard);

        // Panel Izquierdo: Identidad Visual + Holograma Binario en Vivo (sin textos cortados ni badges inferiores)
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
            ActiveAlgorithmLabel = NodeRuntimeState.CurrentNodeId,
            StatusSubtitle = "Núcleo Criptográfico Holográfico v2.0 • Listo"
        };

        leftPanel.Controls.Add(_previewHologram);
        leftPanel.Controls.Add(lblTagline);
        leftPanel.Controls.Add(lblBrand);

        // Panel Derecho: Formulario Limpio (Solo 2 botones: Iniciar Sesión y Registrar Nuevo Integrante)
        var rightPanel = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = HologramTheme.PanelGlass,
            Padding = new Padding(44, 42, 44, 34)
        };

        var lblTitle = new Label
        {
            Text = "Iniciar Sesión",
            Font = new Font("Segoe UI", 20f, FontStyle.Bold),
            ForeColor = HologramTheme.TextPrimary,
            Location = new Point(44, 38),
            Size = new Size(400, 46),
            AutoEllipsis = false
        };

        var lblSub = new Label
        {
            Text = "Acceso al Nodo Criptográfico",
            Font = new Font("Segoe UI", 10.5f, FontStyle.Regular),
            ForeColor = HologramTheme.TextSecondary,
            Location = new Point(44, 86),
            Size = new Size(400, 28),
            AutoEllipsis = false
        };

        var lblUser = CreateFieldLabel("USUARIO", 44, 138);
        _txtUsername = new TextBox
        {
            Location = new Point(44, 164),
            Size = new Size(395, 34),
            BackColor = HologramTheme.PanelInput,
            ForeColor = HologramTheme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Segoe UI", 11.5f),
            Text = "",
            PlaceholderText = "Ingresa tu usuario"
        };

        var lblPass = CreateFieldLabel("CONTRASEÑA", 44, 218);
        _txtPassword = new TextBox
        {
            Location = new Point(44, 244),
            Size = new Size(395, 34),
            BackColor = HologramTheme.PanelInput,
            ForeColor = HologramTheme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Segoe UI", 11.5f),
            UseSystemPasswordChar = true,
            Text = "",
            PlaceholderText = "Ingresa tu contraseña"
        };

        _lblFeedback = new Label
        {
            Text = "",
            Font = new Font("Segoe UI", 9.2f),
            ForeColor = HologramTheme.Danger,
            Location = new Point(44, 292),
            Size = new Size(395, 36)
        };

        var btnLogin = new NeonButton
        {
            Text = "Iniciar Sesión",
            Variant = NeonButtonVariant.Primary,
            AutoFitWidth = false,
            Location = new Point(44, 340),
            Size = new Size(395, 46),
            Font = new Font("Segoe UI", 10.2f, FontStyle.Bold)
        };
        btnLogin.Click += (_, _) => HandleLogin();

        var btnRegister = new NeonButton
        {
            Text = "Registrar Nuevo Integrante",
            Variant = NeonButtonVariant.Secondary,
            AutoFitWidth = false,
            Location = new Point(44, 400),
            Size = new Size(395, 46),
            Font = new Font("Segoe UI", 9.8f, FontStyle.Bold)
        };
        btnRegister.Click += (_, _) => OpenRegisterModal();

        rightPanel.Controls.AddRange(new Control[]
        {
            lblTitle, lblSub,
            lblUser, _txtUsername,
            lblPass, _txtPassword,
            _lblFeedback,
            btnLogin, btnRegister
        });

        _mainCard.Controls.Add(rightPanel);
        _mainCard.Controls.Add(leftPanel);

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

    private static Label CreateFieldLabel(string text, int x, int y) => new()
    {
        Text = text,
        Font = new Font("Segoe UI", 8.8f, FontStyle.Bold),
        ForeColor = HologramTheme.HologramViolet,
        Location = new Point(x, y),
        Size = new Size(395, 24)
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

        // 1. Fondo Base #0B0914
        g.Clear(HologramTheme.BackgroundBase);

        // 2. Cascada de caracteres criptográficos (estela violeta #7D5FFF/#6C5CE7 y cabeza azul cian #00D2FF)
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
                    // Cabeza de gota en azul cian eléctrico #00D2FF
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

        // 3. Línea de escaneo horizontal (Scanline)
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
        // Manejado en OnPaint con Doble Búfer para evitar parpadeos
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
