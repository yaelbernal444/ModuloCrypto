using Microsoft.EntityFrameworkCore;
using ModuloCrypto.Core.Contracts;
using ModuloCrypto.Core.Data;
using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using ModuloCrypto.Network.Shared;
using ModuloCrypto.Network.V1;
using ModuloCrypto.Network.V2;
using ModuloCrypto.Security;
using ModuloCrypto.Security.Strategies;
using ModuloCrypto.UI.Controls;
using ModuloCrypto.UI.Theme;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows.Forms;

namespace ModuloCrypto.UI.Forms;

public partial class FormDashboard : Form
{
    public bool SignOutRequested { get; private set; }

    private static readonly HashSet<string> PlainTextExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".txt", ".json", ".csv", ".xml", ".md", ".log", ".cs", ".html", ".css", ".js"
    };

    private static readonly HashSet<string> ImageViewerExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".png", ".jpg", ".jpeg", ".bmp"
    };

    private readonly Usuario _currentUser;
    private readonly INodeProtocolRuntime _runtime;
    private readonly string _userFullName;
    private readonly ToolTip _dashboardToolTip = new();
    private readonly Font _logoGlyphFont = new("Segoe UI Symbol", 15f, FontStyle.Bold);
    private readonly Font _logoTitleFont = new("Segoe UI", 14f, FontStyle.Bold);
    private readonly Font _logoSubFont = new("Cascadia Mono", 7.8f, FontStyle.Bold);
    private readonly Font _avatarInitialsFont = new("Segoe UI", 11f, FontStyle.Bold);

    // Navigation & Shell
    private readonly Dictionary<string, SidebarNavButton> _navButtons = new();
    private readonly Dictionary<string, Panel> _views = new();
    private SidebarNavButton _navSolicitudes = null!;
    private Panel _viewHost = null!;
    private ComboBox _cmbAlgorithm = null!;
    private StatusPill _pillApi = null!;
    private StatusPill _pillSqlite = null!;
    private StatusPill _pillCert = null!;

    // Dashboard / Crypto Stage Controls
    private HologramLockControl _hologram = null!;
    private Label _lblFileBadge = null!;
    private Label _lblVerificationBanner = null!;
    private TextBox _txtPassphrase = null!;
    private TextBox _txtDataViewer = null!;
    private PictureBox _picImageViewer = null!;
    private NeonButton _btnModeText = null!;
    private NeonButton _btnModeHex = null!;
    private NeonButton _btnModeImg = null!;
    private NeonButton _btnOpenFile = null!;
    private CheckBox _chkAutoDownloadBinary = null!;
    private string _viewerMode = "TEXT";

    // Metadata (V1 / V2 Traceability)
    private TextBox _txtMetaPacketId = null!;
    private TextBox _txtMetaRootNode = null!;
    private Label _lblMetaSignatureBadge = null!;
    private TextBox _txtMetaHops = null!;
    private TextBox _txtMetaKeyRef = null!;
    private TextBox _txtMetaPublicJson = null!;
    private ComboBox _cmbTargetPeer = null!;

    // Current working payload state
    private byte[] _currentBytes;
    private string _currentFileName = "mensaje_seguro.txt";
    private string _currentExtension = ".txt";
    private RegistroCifrado? _activeRecord;
    private bool _isShowingEncrypted;
    private bool _isFromNetworkUntrusted;
    private string? _lastSavedDecryptedPath;
    private string? _binarySummaryReport;

    // Contexto para reenvío / salto intermedio
    private string? _relayProducerNode;
    private string? _relayRootSignatureBase64;
    private string? _relayRootCertBase64;
    private string? _relayRemoteDecryptLink;
    private string? _relaySourceZipPath;
    private List<string>? _relayHopHistory;

    private readonly System.Windows.Forms.Timer _networkMonitorTimer;
    private readonly HashSet<string> _alertedTofuMismatches = new(StringComparer.OrdinalIgnoreCase);

    public FormDashboard(Usuario currentUser, INodeProtocolRuntime? runtime = null)
    {
        _currentUser = currentUser;
        _runtime = runtime ?? NodeRuntimeState.ActiveRuntime ?? (NodeRuntimeState.IsV2 ? new V2ProtocolRuntime() : new V1ProtocolRuntime());
        _currentUser.NodoAsignado = NodeRuntimeState.CurrentNodeId;

        _userFullName = string.IsNullOrWhiteSpace(currentUser.NombreCompleto)
            ? currentUser.NombreUsuario
            : currentUser.NombreCompleto;

        _currentBytes = Encoding.UTF8.GetBytes(
            NodeRuntimeState.IsV2
                ? $"Mensaje confidencial ModuloCrypto — Estándar de Comunicación v2.0 ({NodeRuntimeState.CurrentNodeId})."
                : $"Mensaje confidencial ModuloCrypto — Versión 1.0 ({NodeRuntimeState.CurrentNodeId}).");

        Text = $"ModuloCrypto — {NodeRuntimeState.CurrentNodeId} (v{NodeRuntimeState.ProtocolVersion})";
        WindowState = FormWindowState.Maximized;
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(1240, 740);
        BackColor = HologramTheme.BackgroundBase;
        ForeColor = HologramTheme.TextPrimary;
        DoubleBuffered = true;

        NodeRuntimeState.SqliteConnected = AppDbContext.TestConnection(out string diag);
        NodeRuntimeState.SqliteDiagnostic = diag;

        BuildShellLayout();
        BuildDashboardCryptoView();
        BuildSolicitudesView();
        BuildConsultasView();
        BuildNetworkView();
        BuildSettingsView();

        RefreshActiveIpCardUi();
        UpdateSqlitePillState();
        SwitchView("dashboard");
        RefreshPendingSolicitudesBadge();
        RefreshAllDataViews();
        RenderCurrentBytesInViewer();

        NodeRuntimeState.OnPacketReceived += HandleIncomingPacketEvent;
        NodeRuntimeState.OnPeerDiscoveredOrChanged += HandlePeerChangedEvent;
        NetworkAddressService.OnNetworkEndpointsChanged += HandleNetworkEndpointsChangedEvent;

        _networkMonitorTimer = new System.Windows.Forms.Timer { Interval = 30_000 };
        _networkMonitorTimer.Tick += async (_, _) => await RunPeriodicNetworkMonitorTickAsync();
        _networkMonitorTimer.Start();

        Shown += async (_, _) =>
        {
            if (!_runtime.IsApiOnline && !string.IsNullOrWhiteSpace(_runtime.LastStartupError))
            {
                HologramDialog.ShowWarning(this,
                    $"El servidor HTTP embebido no pudo escuchar en http://0.0.0.0:{NodeRuntimeState.ApiPort}.\n\n" +
                    $"Detalle: {_runtime.LastStartupError}\n\n" +
                    $"Verifica que ningún otro proceso ocupe el puerto {NodeRuntimeState.ApiPort} o los permisos del Firewall de Windows.",
                    $"Advertencia de Puerto HTTP :{NodeRuntimeState.ApiPort}");
            }

            // Primer escaneo ligero no bloqueante tras abrir el Dashboard
            await RunPeriodicNetworkMonitorTickAsync();
        };

        FormClosed += (_, _) =>
        {
            _networkMonitorTimer.Stop();
            _networkMonitorTimer.Dispose();
            NodeRuntimeState.OnPacketReceived -= HandleIncomingPacketEvent;
            NodeRuntimeState.OnPeerDiscoveredOrChanged -= HandlePeerChangedEvent;
            NetworkAddressService.OnNetworkEndpointsChanged -= HandleNetworkEndpointsChangedEvent;
            _dashboardToolTip.Dispose();
            _logoGlyphFont.Dispose();
            _logoTitleFont.Dispose();
            _logoSubFont.Dispose();
            _avatarInitialsFont.Dispose();
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
            try
            {
                _networkMonitorTimer.Stop();
                _networkMonitorTimer.Dispose();
            }
            catch { }

            NodeRuntimeState.OnPacketReceived -= HandleIncomingPacketEvent;
            NodeRuntimeState.OnPeerDiscoveredOrChanged -= HandlePeerChangedEvent;
            NetworkAddressService.OnNetworkEndpointsChanged -= HandleNetworkEndpointsChangedEvent;

            try
            {
                var img = _picImageViewer?.Image;
                if (_picImageViewer != null) _picImageViewer.Image = null;
                img?.Dispose();
            }
            catch { }

            _dashboardToolTip.Dispose();
            _logoGlyphFont.Dispose();
            _logoTitleFont.Dispose();
            _logoSubFont.Dispose();
            _avatarInitialsFont.Dispose();
        }
        base.Dispose(disposing);
    }

    internal bool VerifyCleanResetSnapshot()
    {
        return _activeRecord == null &&
               _currentBytes.Length == 0 &&
               !_isShowingEncrypted &&
               _binarySummaryReport == null &&
               _lastSavedDecryptedPath == null &&
               _picImageViewer.Image == null &&
               string.IsNullOrEmpty(_txtPassphrase.Text) &&
               string.IsNullOrEmpty(_txtDataViewer.Text) &&
               _lblFileBadge.Text == "VISOR • Listo (0 B) [PLANO]" &&
               _txtMetaPacketId.Text == "---" &&
               _txtMetaPublicJson.Text == "{}" &&
               _hologram.CurrentState == HologramState.Idle;
    }

    private void UpdateSqlitePillState()
    {
        if (_pillSqlite == null) return;
        _pillSqlite.Text = NodeRuntimeState.SqliteConnected ? "SQLite: Conectado" : "SQLite: Error";
        _pillSqlite.IsActive = NodeRuntimeState.SqliteConnected;
        _pillSqlite.AutoAdjustWidth();
        _dashboardToolTip.SetToolTip(_pillSqlite, $"BD: {AppDbContext.DatabasePath}\nDiagnóstico: {NodeRuntimeState.SqliteDiagnostic}");
    }

    private void BuildShellLayout()
    {
        // 1. Sidebar Izquierdo (274 px de ancho)
        var sidebar = new Panel
        {
            Dock = DockStyle.Left,
            Width = 274,
            BackColor = HologramTheme.PanelGlass,
            Padding = new Padding(0)
        };
        sidebar.Paint += (_, e) =>
        {
            using var pen = new Pen(HologramTheme.BorderSubtle, 1f);
            e.Graphics.DrawLine(pen, sidebar.Width - 1, 0, sidebar.Width - 1, sidebar.Height);
        };

        var logoPanel = new Panel
        {
            Dock = DockStyle.Top,
            Height = 86,
            BackColor = HologramTheme.PanelGlass
        };
        logoPanel.Paint += (_, e) =>
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

            var iconRect = new Rectangle(16, 22, 38, 38);
            using var path = HologramTheme.CreateRoundedPath(iconRect, 10);
            using var brush = new LinearGradientBrush(iconRect, HologramTheme.AccentStart, HologramTheme.HologramCyan, 135f);
            g.FillPath(brush, path);
            TextRenderer.DrawText(g, "◈", _logoGlyphFont, iconRect, Color.White,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix);

            TextRenderer.DrawText(g, "ModuloCrypto", _logoTitleFont,
                new Rectangle(62, 18, 200, 26), HologramTheme.TextPrimary,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.NoPrefix);

            string subLabel = $"{NodeRuntimeState.CurrentNodeId} • v{NodeRuntimeState.ProtocolVersion}";

            TextRenderer.DrawText(g, subLabel, _logoSubFont,
                new Rectangle(62, 45, 200, 18), HologramTheme.HologramCyan,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.NoPrefix);

            using var sepPen = new Pen(HologramTheme.BorderSubtle, 1f);
            g.DrawLine(sepPen, 16, logoPanel.Height - 1, logoPanel.Width - 16, logoPanel.Height - 1);
        };

        // Tarjeta de Perfil Inferior simplificada a 3 elementos exactos:
        // 1. Avatar circular + Nombre completo
        // 2. Estado "● Online" en verde
        // 3. Botón "Cerrar Sesión"
        var profileWrap = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 144,
            Padding = new Padding(12, 8, 12, 14),
            BackColor = HologramTheme.PanelGlass
        };
        var profileCard = new GlassPanel
        {
            Dock = DockStyle.Fill,
            CornerRadius = 14,
            FillColorTop = HologramTheme.PanelGlassLight,
            FillColorBottom = HologramTheme.PanelGlass,
            BorderColor = HologramTheme.AccentStart,
            NeonBorderGlow = true,
            Padding = new Padding(12, 10, 12, 10)
        };

        var btnLogout = new NeonButton
        {
            Text = "Cerrar Sesión",
            Variant = NeonButtonVariant.Secondary,
            AutoFitWidth = false,
            Dock = DockStyle.Bottom,
            Height = 36,
            CornerRadius = 9
        };
        btnLogout.Click += (_, _) =>
        {
            SignOutRequested = true;
            Close();
        };

        var profileInfoTable = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 2,
            BackColor = HologramTheme.PanelGlassLight,
            Padding = new Padding(0, 2, 0, 6)
        };
        profileInfoTable.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 52f));
        profileInfoTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
        profileInfoTable.RowStyles.Add(new RowStyle(SizeType.Absolute, 26f));
        profileInfoTable.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));

        var avatarBox = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = HologramTheme.PanelGlassLight
        };
        avatarBox.Paint += (_, e) =>
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            var avRect = new Rectangle(2, 2, 42, 42);
            using var avBrush = new LinearGradientBrush(avRect, HologramTheme.AccentStart, HologramTheme.HologramCyan, 135f);
            g.FillEllipse(avBrush, avRect);
            using var ringPen = new Pen(HologramTheme.HologramCyan, 1.5f);
            g.DrawEllipse(ringPen, avRect);

            string initials = BuildInitials(_userFullName);
            TextRenderer.DrawText(g, initials, _avatarInitialsFont, avRect, Color.White,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix);

            using var dotGlow = new SolidBrush(Color.FromArgb(90, HologramTheme.Success));
            g.FillEllipse(dotGlow, 32, 32, 14, 14);
            using var dot = new SolidBrush(HologramTheme.Success);
            g.FillEllipse(dot, 35, 35, 8, 8);
        };
        profileInfoTable.Controls.Add(avatarBox, 0, 0);
        profileInfoTable.SetRowSpan(avatarBox, 2);

        var lblProfName = new Label
        {
            Text = _userFullName,
            Font = new Font("Segoe UI", 10f, FontStyle.Bold),
            ForeColor = HologramTheme.TextPrimary,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.BottomLeft,
            BackColor = HologramTheme.PanelGlassLight,
            AutoEllipsis = true
        };
        var lblProfStatus = new Label
        {
            Text = "● Online",
            Font = new Font("Segoe UI", 8.8f, FontStyle.Bold),
            ForeColor = HologramTheme.Success,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.TopLeft,
            Padding = new Padding(0, 2, 0, 0),
            BackColor = HologramTheme.PanelGlassLight,
            AutoEllipsis = false
        };

        profileInfoTable.Controls.Add(lblProfName, 1, 0);
        profileInfoTable.Controls.Add(lblProfStatus, 1, 1);

        profileCard.Controls.Add(profileInfoTable);
        profileCard.Controls.Add(btnLogout);
        profileWrap.Controls.Add(profileCard);

        var navContainer = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = HologramTheme.PanelGlass
        };

        var navItems = new (string key, string glyph, string text)[]
        {
            ("dashboard", "◆", "Dashboard"),
            ("inbox",     "✉", "Solicitudes"),
            ("history",   "▤", "Consultas"),
            ("network",   "◎", "Red de Nodos"),
            ("settings",  "⚙", "Ajustes")
        };

        int curY = 16;
        foreach (var item in navItems)
        {
            var btn = CreateNavButton(item.key, item.glyph, item.text);
            btn.Location = new Point(12, curY);
            btn.Size = new Size(250, 46);
            navContainer.Controls.Add(btn);
            curY += 46 + 12;
        }
        _navSolicitudes = _navButtons["inbox"];

        sidebar.Controls.Add(navContainer);
        sidebar.Controls.Add(profileWrap);
        sidebar.Controls.Add(logoPanel);

        // 2. Contenedor Principal Derecho (Topbar limpio de 2 filas sin panel de IP + ViewHost)
        var mainRight = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = HologramTheme.BackgroundBase
        };

        var topbar = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            MinimumSize = new Size(0, 108),
            ColumnCount = 2,
            RowCount = 2,
            BackColor = HologramTheme.PanelGlass,
            Padding = new Padding(22, 12, 22, 10)
        };
        topbar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
        topbar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        topbar.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        topbar.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        topbar.Paint += (_, e) =>
        {
            using var pen = new Pen(HologramTheme.BorderSubtle, 1f);
            e.Graphics.DrawLine(pen, 0, topbar.Height - 1, topbar.Width, topbar.Height - 1);
        };

        // Fila 0, Col 0: Saludo y subtítulo compacto con holgura vertical para no recortarse
        var greetingStack = new Panel
        {
            Dock = DockStyle.Fill,
            Height = 58,
            BackColor = HologramTheme.PanelGlass
        };
        var lblWelcome = new Label
        {
            Text = $"Bienvenido, {_userFullName}",
            Font = new Font("Segoe UI", 14.5f, FontStyle.Bold),
            ForeColor = HologramTheme.TextPrimary,
            Dock = DockStyle.Top,
            Height = 32,
            TextAlign = ContentAlignment.MiddleLeft,
            BackColor = HologramTheme.PanelGlass,
            AutoEllipsis = true
        };
        string subWelcomeText = NodeRuntimeState.IsV2
            ? $"{NodeRuntimeState.CurrentNodeId} • Versión 2.0 • {string.Join(", ", NodeRuntimeState.OwnedAlgorithms)}"
            : $"{NodeRuntimeState.CurrentNodeId} • Versión 1.0";

        var lblSubWelcome = new Label
        {
            Text = subWelcomeText,
            Font = new Font("Segoe UI", 9.2f, FontStyle.Bold),
            ForeColor = HologramTheme.HologramCyan,
            Dock = DockStyle.Top,
            Height = 24,
            TextAlign = ContentAlignment.MiddleLeft,
            BackColor = HologramTheme.PanelGlass,
            AutoEllipsis = true
        };
        greetingStack.Controls.Add(lblSubWelcome);
        greetingStack.Controls.Add(lblWelcome);

        // Fila 0, Col 1: Selector ALGORITMO ACTIVO
        var algPanel = new Panel
        {
            Size = new Size(320, 58),
            Margin = new Padding(12, 0, 0, 0),
            BackColor = HologramTheme.PanelGlass
        };
        var lblAlgCap = new Label
        {
            Text = "ALGORITMO ACTIVO",
            Font = new Font("Cascadia Mono", 8.5f, FontStyle.Bold),
            ForeColor = HologramTheme.HologramViolet,
            Dock = DockStyle.Top,
            Height = 22,
            TextAlign = ContentAlignment.MiddleLeft,
            BackColor = HologramTheme.PanelGlass,
            AutoEllipsis = false
        };
        _cmbAlgorithm = new ComboBox
        {
            Dock = DockStyle.Top,
            Height = 32,
            Font = new Font("Cascadia Mono", 9.2f, FontStyle.Bold)
        };
        HologramTheme.StyleComboBox(_cmbAlgorithm, HologramTheme.HologramCyan);
        foreach (var alg in CryptoCatalog.OfficialAlgorithms)
            _cmbAlgorithm.Items.Add(alg);
        _cmbAlgorithm.SelectedIndex = 0;
        _cmbAlgorithm.SelectedIndexChanged += (_, _) => UpdateSelectedAlgorithmHud();
        algPanel.Controls.Add(_cmbAlgorithm);
        algPanel.Controls.Add(lblAlgCap);

        // Fila 1 (Span 2 columnas): FlowLayoutPanel con las 3 píldoras concisas
        var pillsFlow = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = true,
            AutoSize = true,
            Padding = new Padding(0, 6, 0, 2),
            BackColor = HologramTheme.PanelGlass
        };
        _pillApi = new StatusPill
        {
            Text = NodeRuntimeState.ApiOnline ? $"API :{NodeRuntimeState.ApiPort}" : "API: Offline",
            IsActive = NodeRuntimeState.ApiOnline,
            Margin = new Padding(0, 2, 10, 2)
        };
        _pillSqlite = new StatusPill
        {
            Text = NodeRuntimeState.SqliteConnected ? "SQLite: Conectado" : "SQLite: Error",
            IsActive = NodeRuntimeState.SqliteConnected,
            Margin = new Padding(0, 2, 10, 2)
        };
        _pillCert = new StatusPill
        {
            Text = NodeRuntimeState.CertificateActive ? "X.509: Activo" : "X.509: Inactivo",
            IsActive = NodeRuntimeState.CertificateActive,
            Margin = new Padding(0, 2, 10, 2)
        };
        pillsFlow.Controls.AddRange(new Control[] { _pillApi, _pillSqlite, _pillCert });

        topbar.Controls.Add(greetingStack, 0, 0);
        topbar.Controls.Add(algPanel, 1, 0);
        topbar.Controls.Add(pillsFlow, 0, 1);
        topbar.SetColumnSpan(pillsFlow, 2);

        _viewHost = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = HologramTheme.BackgroundBase,
            Padding = new Padding(16)
        };

        mainRight.Controls.Add(_viewHost);
        mainRight.Controls.Add(topbar);

        Controls.Add(mainRight);
        Controls.Add(sidebar);
    }

    private static string BuildInitials(string fullName)
    {
        if (string.IsNullOrWhiteSpace(fullName)) return "MC";
        var parts = fullName.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length >= 2)
            return $"{char.ToUpperInvariant(parts[0][0])}{char.ToUpperInvariant(parts[1][0])}";
        return fullName.Length >= 2 ? fullName[..2].ToUpperInvariant() : fullName.ToUpperInvariant();
    }

    private SidebarNavButton CreateNavButton(string key, string glyph, string text)
    {
        var btn = new SidebarNavButton
        {
            NavKey = key,
            IconGlyph = glyph,
            Text = text
        };
        btn.Click += (_, _) => SwitchView(key);
        _navButtons[key] = btn;
        return btn;
    }

    private void SwitchView(string key)
    {
        foreach (var kv in _navButtons)
            kv.Value.IsActive = kv.Key == key;

        foreach (var kv in _views)
            kv.Value.Visible = kv.Key == key;

        if (key == "inbox")
        {
            RefreshSolicitudesGrid();
            RefreshPendingSolicitudesBadge();
            RefreshConsultasGrid();
        }
        else if (key == "history")
        {
            RefreshSolicitudesGrid();
            RefreshPendingSolicitudesBadge();
            RefreshConsultasGrid();
        }
        else if (key == "network")
        {
            RefreshNetworkGrid();
        }
        else if (key == "settings")
        {
            RefreshSettingsStats();
        }
    }

    private void BuildDashboardCryptoView()
    {
        var panel = new Panel { Dock = DockStyle.Fill, BackColor = HologramTheme.BackgroundBase };
        _views["dashboard"] = panel;
        _viewHost.Controls.Add(panel);

        var split = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            BackColor = HologramTheme.BackgroundBase
        };
        split.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 51f));
        split.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 49f));
        split.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));

        // === COLUMNA IZQUIERDA: HOLOGRAMA 3D BINARIO + PANEL DE ACCIONES (182 px) ===
        var leftCol = new Panel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(0, 0, 10, 0),
            BackColor = HologramTheme.BackgroundBase
        };

        var holoCard = new GlassPanel
        {
            Dock = DockStyle.Fill,
            CornerRadius = 18,
            NeonBorderGlow = true,
            BorderColor = Color.FromArgb(100, HologramTheme.AccentGlow),
            Padding = new Padding(10)
        };

        _hologram = new HologramLockControl
        {
            Dock = DockStyle.Fill,
            ActiveAlgorithmLabel = "AESGCM",
            StatusSubtitle = string.Empty
        };

        holoCard.Controls.Add(_hologram);

        var actionCard = new GlassPanel
        {
            Dock = DockStyle.Bottom,
            Height = 182,
            CornerRadius = 16,
            Padding = new Padding(14)
        };

        var actionGrid = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 3,
            RowCount = 3,
            BackColor = HologramTheme.PanelGlass
        };
        actionGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
        actionGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
        actionGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.34f));
        actionGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 38f));
        actionGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 48f));
        actionGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 48f));

        _txtPassphrase = HologramTheme.CreateDarkTextBox();
        _txtPassphrase.Dock = DockStyle.Fill;
        _txtPassphrase.PlaceholderText = "Clave opcional (o auto-generar llave criptográfica)";
        _txtPassphrase.Margin = new Padding(4, 5, 6, 5);
        actionGrid.Controls.Add(_txtPassphrase, 0, 0);
        actionGrid.SetColumnSpan(_txtPassphrase, 2);

        _cmbTargetPeer = new ComboBox
        {
            Dock = DockStyle.Fill,
            Font = new Font("Cascadia Mono", 8.5f, FontStyle.Bold),
            Margin = new Padding(4, 5, 4, 5)
        };
        HologramTheme.StyleComboBox(_cmbTargetPeer, HologramTheme.HologramCyan);
        RefreshTargetPeerCombo();
        actionGrid.Controls.Add(_cmbTargetPeer, 2, 0);

        var btnLoadFile = new NeonButton
        {
            Text = "📂 Cargar Archivo",
            Variant = NeonButtonVariant.Secondary,
            Dock = DockStyle.Fill,
            Margin = new Padding(4)
        };
        btnLoadFile.Click += (_, _) => HandleLoadFile();

        var btnEncrypt = new NeonButton
        {
            Text = "🔒 Cifrar Paquete",
            Variant = NeonButtonVariant.Primary,
            Dock = DockStyle.Fill,
            Margin = new Padding(4)
        };
        btnEncrypt.Click += async (_, _) => await HandleEncryptActionAsync(asIntermediateHop: false);

        var btnDecryptLocal = new NeonButton
        {
            Text = "🔓 Descifrar Local",
            Variant = NeonButtonVariant.Success,
            Dock = DockStyle.Fill,
            Margin = new Padding(4)
        };
        btnDecryptLocal.Click += (_, _) => HandleDecryptLocalAction();

        actionGrid.Controls.Add(btnLoadFile, 0, 1);
        actionGrid.Controls.Add(btnEncrypt, 1, 1);
        actionGrid.Controls.Add(btnDecryptLocal, 2, 1);

        var btnRelayEncrypt = new NeonButton
        {
            Text = "🔁 Re-Cifrar Salto",
            Variant = NeonButtonVariant.Cyan,
            Dock = DockStyle.Fill,
            Margin = new Padding(4)
        };
        btnRelayEncrypt.Click += async (_, _) => await HandleEncryptActionAsync(asIntermediateHop: true);

        var btnSendZip = new NeonButton
        {
            Text = "🚀 Enviar .ZIP",
            Variant = NeonButtonVariant.Primary,
            Dock = DockStyle.Fill,
            Margin = new Padding(4)
        };
        btnSendZip.Click += async (_, _) =>
        {
            btnSendZip.Enabled = false;
            try { await HandleSendZipToPeerAsync(); }
            finally { if (!btnSendZip.IsDisposed) btnSendZip.Enabled = true; }
        };

        var btnRemoteDecrypt = new NeonButton
        {
            Text = "🌐 Descifrar Remoto",
            Variant = NeonButtonVariant.Secondary,
            Dock = DockStyle.Fill,
            Margin = new Padding(4)
        };
        btnRemoteDecrypt.Click += async (_, _) =>
        {
            btnRemoteDecrypt.Enabled = false;
            try
            {
                if (NodeRuntimeState.IsV2)
                    await HandleRemoteDecryptActionV2Async();
                else
                    await HandleRemoteDecryptActionV1Async();
            }
            finally
            {
                if (!btnRemoteDecrypt.IsDisposed) btnRemoteDecrypt.Enabled = true;
            }
        };

        actionGrid.Controls.Add(btnRelayEncrypt, 0, 2);
        actionGrid.Controls.Add(btnSendZip, 1, 2);
        actionGrid.Controls.Add(btnRemoteDecrypt, 2, 2);

        actionCard.Controls.Add(actionGrid);

        var spacer = new Panel { Dock = DockStyle.Bottom, Height = 12, BackColor = HologramTheme.BackgroundBase };
        leftCol.Controls.Add(holoCard);
        leftCol.Controls.Add(spacer);
        leftCol.Controls.Add(actionCard);

        // === COLUMNA DERECHA: VISOR + MANIFIESTO ===
        var rightCol = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            Padding = new Padding(8, 0, 0, 0),
            BackColor = HologramTheme.BackgroundBase
        };
        rightCol.RowStyles.Add(new RowStyle(SizeType.Percent, 55f));
        rightCol.RowStyles.Add(new RowStyle(SizeType.Percent, 45f));

        var viewerCard = new GlassPanel
        {
            Dock = DockStyle.Fill,
            CornerRadius = 16,
            Padding = new Padding(14),
            Margin = new Padding(0, 0, 0, 12)
        };

        var viewerHeader = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            ColumnCount = 2,
            RowCount = 1,
            BackColor = HologramTheme.PanelGlass
        };
        viewerHeader.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
        viewerHeader.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        _lblFileBadge = new Label
        {
            Text = "VISOR • mensaje_seguro.txt",
            Font = new Font("Segoe UI", 9.4f, FontStyle.Bold),
            ForeColor = HologramTheme.HologramCyan,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            BackColor = HologramTheme.PanelGlass,
            AutoEllipsis = true
        };

        var modeButtons = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            Margin = new Padding(0),
            BackColor = HologramTheme.PanelGlass
        };
        _btnModeText = new NeonButton { Text = "Texto", CornerRadius = 8, Variant = NeonButtonVariant.Primary, Margin = new Padding(2) };
        _btnModeHex = new NeonButton { Text = "Hex", CornerRadius = 8, Variant = NeonButtonVariant.Secondary, Margin = new Padding(2) };
        _btnModeImg = new NeonButton { Text = "Imagen", CornerRadius = 8, Variant = NeonButtonVariant.Secondary, Margin = new Padding(2) };

        _btnModeText.FitToText(minWidth: 74, height: 30);
        _btnModeHex.FitToText(minWidth: 74, height: 30);
        _btnModeImg.FitToText(minWidth: 78, height: 30);

        _btnModeText.Click += (_, _) => { _binarySummaryReport = null; SetViewerMode("TEXT"); };
        _btnModeHex.Click += (_, _) => SetViewerMode("HEX");
        _btnModeImg.Click += (_, _) => SetViewerMode("IMG");
        modeButtons.Controls.AddRange(new Control[] { _btnModeText, _btnModeHex, _btnModeImg });

        viewerHeader.Controls.Add(_lblFileBadge, 0, 0);
        viewerHeader.Controls.Add(modeButtons, 1, 0);

        var fileActionsContainer = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            ColumnCount = 1,
            RowCount = 2,
            Padding = new Padding(0, 6, 0, 2),
            BackColor = HologramTheme.PanelGlass
        };
        fileActionsContainer.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
        fileActionsContainer.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        fileActionsContainer.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        var fileActionsBar = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            WrapContents = false,
            FlowDirection = FlowDirection.LeftToRight,
            Margin = new Padding(0),
            BackColor = HologramTheme.PanelGlass
        };

        var btnDownloadFile = new NeonButton
        {
            Text = "💾 Descargar Archivo",
            Variant = NeonButtonVariant.Cyan,
            CornerRadius = 8,
            Margin = new Padding(0, 2, 8, 2)
        };
        btnDownloadFile.FitToText(minWidth: 152, height: 32);
        btnDownloadFile.Click += (_, _) => HandleDownloadCurrentFile();

        _btnOpenFile = new NeonButton
        {
            Text = "▶ Abrir Local",
            Variant = NeonButtonVariant.Success,
            CornerRadius = 8,
            Margin = new Padding(0, 2, 8, 2)
        };
        _btnOpenFile.FitToText(minWidth: 120, height: 32);
        _btnOpenFile.Click += (_, _) => HandleOpenCurrentFileInWindows();

        var btnClearViewer = new NeonButton
        {
            Text = "Limpiar",
            Variant = NeonButtonVariant.Secondary,
            CornerRadius = 8,
            Margin = new Padding(0, 2, 0, 2)
        };
        btnClearViewer.FitToText(minWidth: 96, height: 32);
        btnClearViewer.Click += (_, _) => ResetDashboardState();

        _chkAutoDownloadBinary = new CheckBox
        {
            Text = "Auto-descargar multimedia/binarios al descifrar",
            Checked = true,
            AutoSize = true,
            Margin = new Padding(2, 4, 2, 2),
            Font = new Font("Segoe UI", 8.5f),
            ForeColor = HologramTheme.HologramViolet,
            BackColor = HologramTheme.PanelGlass
        };

        fileActionsBar.Controls.AddRange(new Control[] { btnDownloadFile, _btnOpenFile, btnClearViewer });
        fileActionsContainer.Controls.Add(fileActionsBar, 0, 0);
        fileActionsContainer.Controls.Add(_chkAutoDownloadBinary, 0, 1);

        var viewerBody = new Panel { Dock = DockStyle.Fill, Padding = new Padding(0, 4, 0, 0), BackColor = HologramTheme.PanelGlass };
        _txtDataViewer = HologramTheme.CreateDarkTextBox(multiline: true, readOnly: false, mono: true);
        _txtDataViewer.Dock = DockStyle.Fill;
        _txtDataViewer.TextChanged += (_, _) =>
        {
            if (_viewerMode == "TEXT" && !_isShowingEncrypted && _binarySummaryReport == null && _txtDataViewer.Focused)
            {
                _currentBytes = Encoding.UTF8.GetBytes(_txtDataViewer.Text);
                _currentFileName = _currentBytes.Length == 0 ? "nuevo_mensaje.txt" : "mensaje_manual.txt";
                _currentExtension = ".txt";
                _isFromNetworkUntrusted = false;
                _lastSavedDecryptedPath = null;
                _lblFileBadge.Text = _currentBytes.Length == 0
                    ? "VISOR • Listo (0 B) [PLANO]"
                    : $"VISOR • {_currentFileName} ({FormatFileSize(_currentBytes.Length)}) [PLANO]";
            }
        };

        _picImageViewer = new PictureBox
        {
            Dock = DockStyle.Fill,
            SizeMode = PictureBoxSizeMode.Zoom,
            BackColor = HologramTheme.PanelInput,
            Visible = false
        };

        _lblVerificationBanner = new Label
        {
            Dock = DockStyle.Top,
            Height = 44,
            Visible = false,
            Font = new Font("Segoe UI", 9.2f, FontStyle.Bold),
            Padding = new Padding(12, 4, 12, 4),
            TextAlign = ContentAlignment.MiddleLeft
        };

        viewerBody.Controls.Add(_txtDataViewer);
        viewerBody.Controls.Add(_picImageViewer);
        viewerBody.Controls.Add(_lblVerificationBanner);

        viewerCard.Controls.Add(viewerBody);
        viewerCard.Controls.Add(fileActionsContainer);
        viewerCard.Controls.Add(viewerHeader);

        var metaCard = new GlassPanel
        {
            Dock = DockStyle.Fill,
            CornerRadius = 16,
            Padding = new Padding(14)
        };

        var metaHeader = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            ColumnCount = 2,
            RowCount = 1,
            BackColor = HologramTheme.PanelGlass
        };
        metaHeader.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
        metaHeader.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        var lblMetaTitle = new Label
        {
            Text = $"MANIFIESTO v{NodeRuntimeState.ProtocolVersion}",
            Font = new Font("Segoe UI", 9.6f, FontStyle.Bold),
            ForeColor = HologramTheme.HologramViolet,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            BackColor = HologramTheme.PanelGlass,
            AutoEllipsis = false
        };
        _lblMetaSignatureBadge = new Label
        {
            Text = "● X.509 Activo",
            Font = new Font("Cascadia Mono", 8.5f, FontStyle.Bold),
            ForeColor = HologramTheme.HologramCyan,
            AutoSize = true,
            Margin = new Padding(8, 4, 0, 4),
            TextAlign = ContentAlignment.MiddleRight,
            BackColor = HologramTheme.PanelGlass
        };
        metaHeader.Controls.Add(lblMetaTitle, 0, 0);
        metaHeader.Controls.Add(_lblMetaSignatureBadge, 1, 0);

        var metaGrid = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 5,
            Padding = new Padding(0, 6, 0, 0),
            BackColor = HologramTheme.PanelGlass
        };
        metaGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 124));
        metaGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        metaGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        metaGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        metaGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        metaGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        metaGrid.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        _txtMetaPacketId = AddMetaRow(metaGrid, 0, "Packet ID", "---");
        _txtMetaRootNode = AddMetaRow(metaGrid, 1, NodeRuntimeState.IsV2 ? "Productor" : "Nodo Raíz", NodeRuntimeState.CurrentNodeId);
        _txtMetaHops = AddMetaRow(metaGrid, 2, "Ruta", NodeRuntimeState.CurrentNodeId);
        _txtMetaKeyRef = AddMetaRow(metaGrid, 3, NodeRuntimeState.IsV2 ? "KeyRef" : "Link Remoto", $"owner={NodeRuntimeState.CurrentNodeId}");

        var lblPub = new Label
        {
            Text = "Parámetros",
            Font = new Font("Segoe UI", 8.8f, FontStyle.Bold),
            ForeColor = HologramTheme.TextSecondary,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.TopLeft,
            Padding = new Padding(0, 6, 0, 0),
            BackColor = HologramTheme.PanelGlass
        };
        _txtMetaPublicJson = HologramTheme.CreateDarkTextBox(multiline: true, readOnly: true, mono: true);
        _txtMetaPublicJson.Dock = DockStyle.Fill;
        _txtMetaPublicJson.Text = "{}";
        metaGrid.Controls.Add(lblPub, 0, 4);
        metaGrid.Controls.Add(_txtMetaPublicJson, 1, 4);

        metaCard.Controls.Add(metaGrid);
        metaCard.Controls.Add(metaHeader);

        rightCol.Controls.Add(viewerCard, 0, 0);
        rightCol.Controls.Add(metaCard, 0, 1);

        split.Controls.Add(leftCol, 0, 0);
        split.Controls.Add(rightCol, 1, 0);
        panel.Controls.Add(split);

        UpdateSelectedAlgorithmHud();
    }

    private static TextBox AddMetaRow(TableLayoutPanel grid, int row, string label, string initialValue)
    {
        var lbl = new Label
        {
            Text = label,
            Font = new Font("Segoe UI", 8.8f, FontStyle.Bold),
            ForeColor = HologramTheme.TextSecondary,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            BackColor = HologramTheme.PanelGlass
        };
        var txt = HologramTheme.CreateDarkTextBox(multiline: false, readOnly: true, mono: true);
        txt.Dock = DockStyle.Fill;
        txt.Text = initialValue;
        txt.Margin = new Padding(0, 2, 0, 2);
        grid.Controls.Add(lbl, 0, row);
        grid.Controls.Add(txt, 1, row);
        return txt;
    }

    private void UpdateSelectedAlgorithmHud()
    {
        if (_cmbAlgorithm.SelectedItem is CryptoAlgorithmInfo info)
        {
            _hologram.ActiveAlgorithmLabel = info.Code;
        }
    }

    private void SetViewerMode(string mode)
    {
        _viewerMode = mode;
        _btnModeText.Variant = mode == "TEXT" ? NeonButtonVariant.Primary : NeonButtonVariant.Secondary;
        _btnModeHex.Variant = mode == "HEX" ? NeonButtonVariant.Primary : NeonButtonVariant.Secondary;
        _btnModeImg.Variant = mode == "IMG" ? NeonButtonVariant.Primary : NeonButtonVariant.Secondary;
        _btnModeText.Invalidate();
        _btnModeHex.Invalidate();
        _btnModeImg.Invalidate();
        RenderCurrentBytesInViewer();
    }

    private void RenderCurrentBytesInViewer()
    {
        if (_activeRecord == null && _currentBytes.Length == 0 && string.Equals(_currentFileName, "nuevo_mensaje.txt", StringComparison.Ordinal))
            _lblFileBadge.Text = "VISOR • Listo (0 B) [PLANO]";
        else
            _lblFileBadge.Text = $"VISOR • {_currentFileName} ({FormatFileSize(_currentBytes.Length)})" +
                                 (_isShowingEncrypted ? " [CIFRADO]" : " [PLANO]");

        if (_btnOpenFile != null)
            _btnOpenFile.Enabled = !_isFromNetworkUntrusted;

        if (_viewerMode == "IMG")
        {
            _txtDataViewer.Visible = false;
            _picImageViewer.Visible = true;
            try
            {
                using var ms = new MemoryStream(_currentBytes);
                using var img = Image.FromStream(ms);
                _picImageViewer.Image?.Dispose();
                _picImageViewer.Image = new Bitmap(img);
            }
            catch
            {
                _picImageViewer.Image?.Dispose();
                _picImageViewer.Image = null;
                _txtDataViewer.Visible = true;
                _picImageViewer.Visible = false;
                _txtDataViewer.ReadOnly = true;
                _txtDataViewer.Text = "[Los bytes actuales no corresponden a una imagen PNG/BMP/JPG válida.\r\nPrueba el algoritmo LSBSTEGO o carga un archivo de imagen.]";
            }
            return;
        }

        _picImageViewer.Visible = false;
        _txtDataViewer.Visible = true;

        if (_viewerMode == "HEX")
        {
            _txtDataViewer.ReadOnly = true;
            int previewLen = Math.Min(_currentBytes.Length, 4096);
            var sb = new StringBuilder();
            for (int i = 0; i < previewLen; i += 16)
            {
                sb.Append($"{i:X6}  ");
                for (int j = 0; j < 16; j++)
                {
                    if (i + j < previewLen) sb.Append($"{_currentBytes[i + j]:X2} ");
                    else sb.Append("   ");
                }
                sb.Append(" |");
                for (int j = 0; j < 16 && i + j < previewLen; j++)
                {
                    byte b = _currentBytes[i + j];
                    sb.Append(b >= 32 && b <= 126 ? (char)b : '.');
                }
                sb.AppendLine("|");
            }
            if (_currentBytes.Length > previewLen)
                sb.AppendLine($"... (+{_currentBytes.Length - previewLen:N0} bytes omitidos en vista previa HEX)");
            _txtDataViewer.Text = sb.ToString();
        }
        else
        {
            if (!_isShowingEncrypted && !string.IsNullOrEmpty(_binarySummaryReport))
            {
                _txtDataViewer.ReadOnly = true;
                _txtDataViewer.Text = _binarySummaryReport;
                return;
            }

            _txtDataViewer.ReadOnly = _isShowingEncrypted;
            if (_isShowingEncrypted)
            {
                string b64 = Convert.ToBase64String(_currentBytes);
                _txtDataViewer.Text = b64.Length > 12000 ? b64[..12000] + "\r\n...[Base64 truncado en visor]" : b64;
            }
            else
            {
                _txtDataViewer.Text = Encoding.UTF8.GetString(_currentBytes);
            }
        }
    }

    private void HandleLoadFile()
    {
        using var ofd = new OpenFileDialog
        {
            Title = "Seleccionar archivo para cifrar o inspeccionar",
            Filter = "Todos los archivos (*.*)|*.*|Multimedia y Documentos (*.mp4;*.mkv;*.avi;*.mp3;*.wav;*.pdf;*.docx;*.xlsx;*.pptx;*.zip)|*.mp4;*.mkv;*.avi;*.mp3;*.wav;*.pdf;*.docx;*.xlsx;*.pptx;*.zip|Imágenes (*.png;*.bmp;*.jpg;*.jpeg)|*.png;*.bmp;*.jpg;*.jpeg|Texto / JSON (*.txt;*.json;*.csv;*.xml)|*.txt;*.json;*.csv;*.xml"
        };
        if (ofd.ShowDialog(this) != DialogResult.OK) return;

        _currentBytes = File.ReadAllBytes(ofd.FileName);
        _currentFileName = Path.GetFileName(ofd.FileName);
        _currentExtension = Path.GetExtension(ofd.FileName);
        if (string.IsNullOrWhiteSpace(_currentExtension)) _currentExtension = ".bin";
        _isShowingEncrypted = false;
        _isFromNetworkUntrusted = false;
        _lastSavedDecryptedPath = ofd.FileName;
        _binarySummaryReport = null;

        ClearRelayContext();
        HideVerificationBanner();

        _hologram.SetIdle(string.Empty);

        if (ImageViewerExtensions.Contains(_currentExtension))
        {
            SetViewerMode("IMG");
        }
        else if (!PlainTextExtensions.Contains(_currentExtension))
        {
            _binarySummaryReport =
                $"╔══════════════════════════════════════════════════════════════════╗\r\n" +
                $"║  ARCHIVO MULTIMEDIA / BINARIO CARGADO EN MEMORIA                 ║\r\n" +
                $"╚══════════════════════════════════════════════════════════════════╝\r\n\r\n" +
                $"• Archivo Original : {_currentFileName}\r\n" +
                $"• Extensión        : {_currentExtension}\r\n" +
                $"• Tamaño Exacto    : {FormatFileSize(_currentBytes.Length)} ({_currentBytes.Length:N0} bytes)\r\n" +
                $"• Ruta Origen      : {ofd.FileName}\r\n\r\n" +
                $"Listo para cifrar con cualquiera de los 21 algoritmos oficiales o inspeccionar en la pestaña [Hex].";
            SetViewerMode("TEXT");
        }
        else
        {
            SetViewerMode("TEXT");
        }
    }

    private void HandleDownloadCurrentFile()
    {
        if (_currentBytes == null || _currentBytes.Length == 0)
        {
            HologramDialog.ShowInfo(this, "No hay bytes activos en el visor para guardar.");
            return;
        }

        string suggestedName = Path.GetFileName(string.IsNullOrWhiteSpace(_currentFileName) ? $"archivo{_currentExtension}" : _currentFileName);
        string ext = string.IsNullOrWhiteSpace(_currentExtension) ? Path.GetExtension(suggestedName) : _currentExtension;
        if (string.IsNullOrWhiteSpace(ext)) ext = ".bin";

        using var sfd = new SaveFileDialog
        {
            Title = "Guardar archivo en disco",
            FileName = suggestedName,
            DefaultExt = ext.TrimStart('.'),
            Filter = $"Archivo (*{ext})|*{ext}|Todos los archivos (*.*)|*.*"
        };

        if (sfd.ShowDialog(this) != DialogResult.OK) return;

        File.WriteAllBytes(sfd.FileName, _currentBytes);
        _lastSavedDecryptedPath = sfd.FileName;
        HologramDialog.ShowSuccess(this, $"Archivo guardado correctamente:\n{sfd.FileName}\nTamaño: {FormatFileSize(_currentBytes.Length)}",
            "Archivo Guardado");
    }

    private void HandleOpenCurrentFileInWindows()
    {
        if (_isFromNetworkUntrusted)
        {
            HologramDialog.ShowWarning(this,
                "Por política de seguridad, está prohibido abrir o ejecutar directamente archivos recibidos desde la red.\n\n" +
                "Puedes guardar los bytes de forma segura usando [💾 Descargar Archivo] o inspeccionarlos en [Hex].",
                "Política de Seguridad");
            return;
        }

        if (_currentBytes == null || _currentBytes.Length == 0)
        {
            HologramDialog.ShowInfo(this, "No hay ningún archivo local cargado o descifrado para abrir.");
            return;
        }

        try
        {
            string targetPath = _lastSavedDecryptedPath ?? string.Empty;
            if (string.IsNullOrWhiteSpace(targetPath) || !File.Exists(targetPath))
            {
                string decDir = Path.Combine(AppContext.BaseDirectory, "DecryptedFiles");
                Directory.CreateDirectory(decDir);
                targetPath = GetUniqueFilePath(decDir, _currentFileName, _currentExtension);
                File.WriteAllBytes(targetPath, _currentBytes);
                _lastSavedDecryptedPath = targetPath;
            }

            Process.Start(new ProcessStartInfo(targetPath)
            {
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            HologramDialog.ShowError(this, $"No se pudo abrir el archivo con el visor de Windows:\n{ex.Message}");
        }
    }

    /// <summary>
    /// Reinicia únicamente el estado de trabajo actual en el Dashboard sin borrar registros ni historial de SQLite.
    /// </summary>
    public void ResetDashboardState()
    {
        _currentBytes = Array.Empty<byte>();
        _currentFileName = "nuevo_mensaje.txt";
        _currentExtension = ".txt";
        _activeRecord = null;
        _isShowingEncrypted = false;
        _isFromNetworkUntrusted = false;
        _binarySummaryReport = null;
        _lastSavedDecryptedPath = null;

        ClearRelayContext();
        HideVerificationBanner();

        if (_txtPassphrase != null)
            _txtPassphrase.Text = string.Empty;

        if (_picImageViewer != null)
        {
            var oldImg = _picImageViewer.Image;
            _picImageViewer.Image = null;
            oldImg?.Dispose();
            _picImageViewer.Visible = false;
        }

        if (_txtDataViewer != null)
        {
            _txtDataViewer.ReadOnly = false;
            _txtDataViewer.Text = string.Empty;
        }

        SetViewerMode("TEXT");
        if (_lblFileBadge != null)
            _lblFileBadge.Text = "VISOR • Listo (0 B) [PLANO]";

        if (_txtMetaPacketId != null) _txtMetaPacketId.Text = "---";
        if (_txtMetaRootNode != null) _txtMetaRootNode.Text = NodeRuntimeState.CurrentNodeId;
        if (_txtMetaHops != null) _txtMetaHops.Text = NodeRuntimeState.CurrentNodeId;
        if (_txtMetaKeyRef != null)
            _txtMetaKeyRef.Text = NodeRuntimeState.IsV2
                ? $"owner={NodeRuntimeState.CurrentNodeId}"
                : $"owner={NodeRuntimeState.CurrentNodeId}";
        if (_txtMetaPublicJson != null) _txtMetaPublicJson.Text = "{}";
        if (_lblMetaSignatureBadge != null)
        {
            _lblMetaSignatureBadge.Text = "● X.509 Activo";
            _lblMetaSignatureBadge.ForeColor = HologramTheme.HologramCyan;
        }

        _hologram?.SetIdle(string.Empty);

        if (_txtDataViewer != null && _txtDataViewer.CanFocus)
            _txtDataViewer.Focus();
    }

    private void ShowVerificationBanner(bool valid, string? detail)
    {
        if (_lblVerificationBanner == null) return;
        string cleanDetail = string.IsNullOrWhiteSpace(detail)
            ? (valid ? "VERIFICACIÓN VÁLIDA — integridad autenticada." : "VERIFICACIÓN INVÁLIDA — resumen/MAC no coincide.")
            : detail.Trim();

        _lblVerificationBanner.Text = (valid ? "✔ " : "✖ ") + cleanDetail;
        _lblVerificationBanner.BackColor = valid ? Color.FromArgb(14, 58, 42) : Color.FromArgb(61, 20, 28);
        _lblVerificationBanner.ForeColor = valid ? HologramTheme.Success : HologramTheme.Danger;
        _lblVerificationBanner.Visible = true;
    }

    private void HideVerificationBanner()
    {
        if (_lblVerificationBanner != null)
        {
            _lblVerificationBanner.Visible = false;
            _lblVerificationBanner.Text = string.Empty;
        }
    }

    private void ClearRelayContext()
    {
        _relayProducerNode = null;
        _relayRootSignatureBase64 = null;
        _relayRootCertBase64 = null;
        _relayRemoteDecryptLink = null;
        _relaySourceZipPath = null;
        _relayHopHistory = null;
    }

    private async Task HandleEncryptActionAsync(bool asIntermediateHop)
    {
        if (_cmbAlgorithm.SelectedItem is not CryptoAlgorithmInfo algInfo) return;

        try
        {
            HideVerificationBanner();

            if (_viewerMode == "TEXT" && !_isShowingEncrypted && _binarySummaryReport == null)
                _currentBytes = Encoding.UTF8.GetBytes(_txtDataViewer.Text);

            if (NodeRuntimeState.IsV2 &&
                !asIntermediateHop &&
                !NodeRuntimeState.OwnedAlgorithms.Contains(algInfo.Code, StringComparer.OrdinalIgnoreCase))
            {
                var ownerPeer = ResolveBestPeerForAlgorithm(algInfo.Code);
                if (ownerPeer != null && ownerPeer.IsOnline && ownerPeer.IsConfirmed && !ownerPeer.HasThumbprintMismatch)
                {
                    var askDelegate = HologramDialog.ShowQuestion(this,
                        $"El algoritmo {algInfo.Code} pertenece al nodo remoto {ownerPeer.NodeId} ({ownerPeer.BaseUrl}), que está ONLINE y confirmado (TOFU).\n\n" +
                        $"• Pulsa [Sí] para DELEGAR el cifrado remoto a {ownerPeer.NodeId} (POST /api/crypto/forward).\n" +
                        $"• Pulsa [No] para ejecutar el cifrado localmente en {NodeRuntimeState.CurrentNodeId}.",
                        $"Delegación Criptográfica v2.0 — {algInfo.Code}",
                        includeCancel: false);

                    if (askDelegate == DialogResult.Yes)
                    {
                        Cursor = Cursors.WaitCursor;
                        V2AlgorithmProfileDto? profile = null;
                        try
                        {
                            profile = await V2NetworkClient.GetOrFetchPeerAlgorithmProfileAsync(ownerPeer, algInfo.Code, 1500);
                        }
                        finally
                        {
                            Cursor = Cursors.Default;
                        }

                        var modalRes = PromptV2SecretsModal(
                            algInfo.Code,
                            operation: "forward",
                            producerNode: ownerPeer.NodeId,
                            sourceNode: NodeRuntimeState.CurrentNodeId,
                            sigValid: true,
                            profile: profile,
                            pubParams: null,
                            prefillSecret: _txtPassphrase.Text);

                        if (modalRes == null)
                            return;

                        Cursor = Cursors.WaitCursor;
                        (bool Success, V2CryptoForwardResponse? Response, string ErrorMessage) fwd;
                        try
                        {
                            fwd = await V2NetworkClient.CallRemoteForwardAsync(
                                ownerPeer,
                                algInfo.Code,
                                _currentBytes,
                                _currentFileName,
                                _currentExtension,
                                keySizeBits: 256,
                                secretsDictionary: modalRes.SecretsDictionary,
                                options: modalRes.Options);
                        }
                        finally
                        {
                            Cursor = Cursors.Default;
                        }

                        if (!fwd.Success || fwd.Response == null)
                        {
                            HologramDialog.ShowWarning(this,
                                $"El nodo {ownerPeer.NodeId} rechazó la delegación remota ({algInfo.Code}):\n{fwd.ErrorMessage}",
                                "Delegación Remota v2.0");
                            return;
                        }

                        var fwdResp = fwd.Response;
                        byte[] outBytes = _currentBytes;
                        if (!string.IsNullOrWhiteSpace(fwdResp.CiphertextBase64) &&
                            KeyInputParser.TryDecodeFlexibleBase64(fwdResp.CiphertextBase64, out byte[] decodedOut))
                        {
                            outBytes = decodedOut;
                        }

                        string storedSecret = modalRes.LocalSecretKeyString;
                        if (string.IsNullOrWhiteSpace(storedSecret) && fwdResp.SecretKeyEnvelope != null)
                        {
                            try
                            {
                                var opened = V2EnvelopeService.OpenSecretsDictionary(
                                    fwdResp.SecretKeyEnvelope,
                                    fwdResp.RequestId,
                                    fallbackPacketId: fwdResp.PacketId);
                                if (opened.TryGetValue("key", out var kVal) && !string.IsNullOrWhiteSpace(kVal))
                                    storedSecret = kVal;
                                else if (opened.Count > 0)
                                    storedSecret = opened.Values.First();
                            }
                            catch { }
                        }

                        string effProducer = !string.IsNullOrWhiteSpace(fwdResp.ProducerNode)
                            ? fwdResp.ProducerNode.Trim().ToUpperInvariant()
                            : ownerPeer.NodeId;
                        string effPacketId = !string.IsNullOrWhiteSpace(fwdResp.PacketId)
                            ? fwdResp.PacketId
                            : Guid.NewGuid().ToString("D").ToLowerInvariant();
                        string effKeyRef = !string.IsNullOrWhiteSpace(fwdResp.KeyRef?.KeyId)
                            ? fwdResp.KeyRef.KeyId
                            : BuildDefaultKeyLink(effPacketId);
                        string remotePubJson = JsonSerializer.Serialize(fwdResp.PublicParameters);
                        var remoteHops = new List<string> { effProducer };
                        if (!string.Equals(effProducer, NodeRuntimeState.CurrentNodeId, StringComparison.OrdinalIgnoreCase))
                            remoteHops.Add(NodeRuntimeState.CurrentNodeId);

                        var remoteReg = new RegistroCifrado
                        {
                            UsuarioId = _currentUser.Id,
                            PacketId = effPacketId,
                            NombreArchivo = _currentFileName,
                            Extension = _currentExtension,
                            BytesCifrados = Convert.ToBase64String(outBytes),
                            AlgoritmoCodigo = algInfo.Code,
                            ParametrosPublicosJson = remotePubJson,
                            LlaveSecretaBase64 = storedSecret,
                            LinkDescifradoRemoto = effKeyRef,
                            NodoRaiz = effProducer,
                            FirmaRaizBase64 = SignBytesCurrentVersion(outBytes),
                            RutaSaltosJson = JsonSerializer.Serialize(remoteHops),
                            Origen = "Remoto",
                            FechaOperacion = DateTime.Now
                        };

                        using (var db = new AppDbContext())
                        {
                            db.RegistrosCifrados.Add(remoteReg);
                            db.SaveChanges();
                        }

                        _activeRecord = remoteReg;
                        _currentBytes = outBytes;
                        _isShowingEncrypted = true;
                        _binarySummaryReport = null;
                        _lastSavedDecryptedPath = null;

                        _hologram.TriggerEncryptAnimation(algInfo.Code);
                        UpdateMetadataPanel(remoteReg, signatureValid: true);
                        RenderCurrentBytesInViewer();
                        RefreshConsultasGrid();
                        return;
                    }
                }
            }

            string packetId = Guid.NewGuid().ToString("D").ToLowerInvariant();
            var strategy = CryptoCatalog.GetStrategy(algInfo.Code);
            var result = strategy.Encrypt(_currentBytes, _txtPassphrase.Text, NodeRuntimeState.IsV2 ? packetId : null);

            string producerNode;
            string rootSignature;
            string remoteLink;
            List<string> hops;

            if (asIntermediateHop && !string.IsNullOrWhiteSpace(_relayProducerNode))
            {
                producerNode = _relayProducerNode!;
                rootSignature = !string.IsNullOrWhiteSpace(_relayRootSignatureBase64)
                    ? _relayRootSignatureBase64!
                    : SignBytesCurrentVersion(result.OutputBytes);
                remoteLink = !string.IsNullOrWhiteSpace(_relayRemoteDecryptLink)
                    ? _relayRemoteDecryptLink!
                    : BuildDefaultKeyLink(packetId);
                hops = _relayHopHistory != null ? new List<string>(_relayHopHistory) : new List<string> { producerNode };
                if (hops.Count == 0 || hops[^1] != NodeRuntimeState.CurrentNodeId)
                    hops.Add(NodeRuntimeState.CurrentNodeId);
            }
            else
            {
                ClearRelayContext();
                producerNode = NodeRuntimeState.CurrentNodeId;
                rootSignature = SignBytesCurrentVersion(result.OutputBytes);
                remoteLink = BuildDefaultKeyLink(packetId);
                hops = new List<string> { NodeRuntimeState.CurrentNodeId };
            }

            string outExt = string.IsNullOrEmpty(result.OutputExtensionOverride) ? _currentExtension : result.OutputExtensionOverride;
            string outName = string.IsNullOrEmpty(result.OutputExtensionOverride)
                ? _currentFileName
                : Path.ChangeExtension(_currentFileName, outExt);

            var registro = new RegistroCifrado
            {
                UsuarioId = _currentUser.Id,
                PacketId = packetId,
                NombreArchivo = outName,
                Extension = outExt,
                BytesCifrados = Convert.ToBase64String(result.OutputBytes),
                AlgoritmoCodigo = algInfo.Code,
                ParametrosPublicosJson = result.PublicParametersJson,
                LlaveSecretaBase64 = result.SecretKeyBase64,
                LinkDescifradoRemoto = remoteLink,
                NodoRaiz = producerNode,
                FirmaRaizBase64 = rootSignature,
                RutaSaltosJson = JsonSerializer.Serialize(hops),
                Origen = asIntermediateHop && producerNode != NodeRuntimeState.CurrentNodeId ? "Relay" : "Local",
                FechaOperacion = DateTime.Now
            };

            using (var db = new AppDbContext())
            {
                db.RegistrosCifrados.Add(registro);
                db.SaveChanges();
            }

            _activeRecord = registro;
            _currentBytes = result.OutputBytes;
            _currentFileName = outName;
            _currentExtension = outExt;
            _isShowingEncrypted = true;
            _binarySummaryReport = null;
            _lastSavedDecryptedPath = null;

            _hologram.TriggerEncryptAnimation(algInfo.Code);
            UpdateMetadataPanel(registro, signatureValid: true);

            if (algInfo.Code == "LSBSTEGO")
                SetViewerMode("IMG");
            else
                RenderCurrentBytesInViewer();

            RefreshConsultasGrid();
        }
        catch (Exception ex)
        {
            HologramDialog.ShowError(this, $"Error durante el cifrado ({algInfo.Code}):\n{ex.Message}",
                "ModuloCrypto — Error de Cifrado");
        }
    }

    private static string SignBytesCurrentVersion(byte[] data) =>
        NodeRuntimeState.IsV2 ? V2CertificateService.SignDataPss(data) : V1CertificateService.SignPayload(data);

    private static string BuildDefaultKeyLink(string packetId) =>
        NodeRuntimeState.IsV2
            ? V2FormatValidators.BuildKeyId(NodeRuntimeState.CurrentNodeId, packetId)
            : $"http://{NodeRuntimeState.LocalIpAddress}:{NodeRuntimeState.ApiPort}/api/crypto/decrypt/{packetId}";

    private void HandleDecryptLocalAction()
    {
        if (_activeRecord == null)
        {
            HologramDialog.ShowInfo(this, "Primero cifra un paquete o carga un registro desde Consultas / Solicitudes.",
                $"ModuloCrypto — {NodeRuntimeState.CurrentNodeId}");
            return;
        }

        string keyToUse = string.IsNullOrWhiteSpace(_activeRecord.LlaveSecretaBase64)
            ? _txtPassphrase.Text
            : _activeRecord.LlaveSecretaBase64;

        var ctx = new DecryptionContext(
            PacketId: _activeRecord.PacketId,
            OriginalFileName: _activeRecord.NombreArchivo,
            OriginalExtension: _activeRecord.Extension);

        ExecuteDecryption(_activeRecord.AlgoritmoCodigo, _currentBytes, keyToUse, _activeRecord.ParametrosPublicosJson, ctx);
    }

    private async Task HandleRemoteDecryptActionV1Async()
    {
        if (_activeRecord == null)
        {
            HologramDialog.ShowInfo(this, "Carga primero un paquete desde Consultas o Bandeja de Solicitudes.",
                $"ModuloCrypto — {NodeRuntimeState.CurrentNodeId}");
            return;
        }

        var candidateUrls = BuildSilentKeyRecoveryUrls(_activeRecord, ResolveOriginPeersForActiveRecord());
        string lastError = "El nodo emisor no expuso endpoint de recuperación de llave.";

        foreach (string url in candidateUrls)
        {
            var remote = await V1NetworkClient.RequestRemoteKeyAsync(url);
            if (remote.Success && !string.IsNullOrWhiteSpace(remote.LlaveSecretaBase64))
            {
                string effPubJson = !string.IsNullOrWhiteSpace(remote.ParametrosPublicosJson) && remote.ParametrosPublicosJson != "{}"
                    ? remote.ParametrosPublicosJson
                    : _activeRecord.ParametrosPublicosJson;

                string effAlg = !string.IsNullOrWhiteSpace(remote.AlgoritmoCodigo)
                    ? remote.AlgoritmoCodigo
                    : _activeRecord.AlgoritmoCodigo;

                var ctx = new DecryptionContext(
                    PacketId: _activeRecord.PacketId,
                    OriginalFileName: _activeRecord.NombreArchivo,
                    OriginalExtension: _activeRecord.Extension);

                if (ExecuteDecryption(effAlg, _currentBytes, remote.LlaveSecretaBase64, effPubJson, ctx, showErrorMessageBox: false, out string? decErr))
                    return;

                lastError = $"Llave recibida desde {url}, pero el descifrado falló: {decErr}";
            }
            else if (!string.IsNullOrWhiteSpace(remote.Message))
            {
                lastError = $"{url} -> {remote.Message}";
            }
        }

        // Respaldo adicional: si el emisor tiene activo /api/crypto/inverse v2.0, intentarlo silenciosamente
        var (v2Ok, v2Err) = await TrySilentV2InverseOnCandidatePeersAsync();
        if (v2Ok)
            return;

        HologramDialog.ShowWarning(this,
            $"No fue posible completar el Descifrado Remoto automático del paquete {_activeRecord.PacketId}:\n\n" +
            $"• Recuperación de llave: {lastError}\n" +
            $"• Servicio inverse: {v2Err}",
            "Descifrado Remoto");
    }

    /// <summary>
    /// Flujo silencioso v2.0 de Descifrado Remoto (respaldo automático sin diálogos de confirmación ni envío a bandeja Solicitudes):
    /// - Paso A: Identifica automáticamente el nodo productor/emisor (incl. v3-local y publicParameters["keyId"]) o dueño Tabla 4.1
    ///   y envía directamente POST /api/crypto/inverse (200 directo o 202 con polling /api/jobs/{jobId}).
    /// - Paso B: Si el Paso A no devuelve el resultado, solicita silenciosamente GET http://&lt;ip&gt;:&lt;puerto&gt;/api/crypto/decrypt/{packetId}
    ///   (o LinkDescifradoRemoto) y descifra localmente con alias tolerantes.
    /// - Paso C: Si el nodo remoto está apagado o rechaza, muestra un único diálogo oscuro claro sin corromper el paquete cargado.
    /// </summary>
    private async Task HandleRemoteDecryptActionV2Async()
    {
        if (_activeRecord == null)
        {
            HologramDialog.ShowInfo(this,
                "Primero cifra un paquete o carga un paquete .zip desde Solicitudes o Consultas.",
                $"Descifrado Remoto — {NodeRuntimeState.CurrentNodeId}");
            return;
        }

        // Paso A: Intentar silenciosamente POST /api/crypto/inverse en el nodo emisor/productor o dueño del algoritmo
        var (stepAOk, stepAError) = await TrySilentV2InverseOnCandidatePeersAsync();
        if (stepAOk)
            return;

        // Paso B: Respaldo silencioso de recuperación de llave vía GET /api/crypto/decrypt/{packetId} o LinkDescifradoRemoto
        var candidatePeers = ResolveOriginPeersForActiveRecord();
        var keyUrls = BuildSilentKeyRecoveryUrls(_activeRecord, candidatePeers);
        string stepBError = "El nodo emisor no devolvió llave en /api/crypto/decrypt/{packetId}.";

        byte[] cipherBytes = Convert.FromBase64String(_activeRecord.BytesCifrados);

        foreach (string url in keyUrls)
        {
            var remote = await V1NetworkClient.RequestRemoteKeyAsync(url);
            if (remote.Success && !string.IsNullOrWhiteSpace(remote.LlaveSecretaBase64))
            {
                string effPubJson = !string.IsNullOrWhiteSpace(_activeRecord.ParametrosPublicosJson) && _activeRecord.ParametrosPublicosJson != "{}"
                    ? _activeRecord.ParametrosPublicosJson
                    : remote.ParametrosPublicosJson;

                var ctx = new DecryptionContext(
                    PacketId: _activeRecord.PacketId,
                    OriginalFileName: _activeRecord.NombreArchivo,
                    OriginalExtension: _activeRecord.Extension);

                if (ExecuteDecryption(
                    _activeRecord.AlgoritmoCodigo,
                    cipherBytes,
                    remote.LlaveSecretaBase64,
                    effPubJson,
                    ctx,
                    showErrorMessageBox: false,
                    out string? decErr))
                {
                    return;
                }

                stepBError = $"Llave obtenida de {url}, pero el descifrado local falló: {decErr}";
            }
            else if (!string.IsNullOrWhiteSpace(remote.Message))
            {
                stepBError = $"{url} -> {remote.Message}";
            }
        }

        // Paso C: Único diálogo oscuro claro sin alterar ni corromper el paquete cargado
        HologramDialog.ShowWarning(this,
            $"El nodo emisor ({_activeRecord.NodoRaiz}) no devolvió el resultado ni la llave para el paquete '{_activeRecord.PacketId}' ({_activeRecord.AlgoritmoCodigo}):\n\n" +
            $"• POST /api/crypto/inverse : {stepAError}\n" +
            $"• GET /api/crypto/decrypt  : {stepBError}\n\n" +
            $"El paquete permanece cargado intacto en el Dashboard para que puedas ingresar una clave manualmente o reintentar cuando el nodo emisor esté activo.",
            "Descifrado Remoto — Respuesta del Nodo Emisor");
    }

    private async Task<(bool Success, string DiagnosticError)> TrySilentV2InverseOnCandidatePeersAsync()
    {
        string diagnosticError = "Ningún nodo candidato respondió en POST /api/crypto/inverse.";
        if (_activeRecord == null) return (false, diagnosticError);

        string algCode = _activeRecord.AlgoritmoCodigo.Trim().ToUpperInvariant();
        byte[] cipherBytes;
        try
        {
            cipherBytes = Convert.FromBase64String(_activeRecord.BytesCifrados);
        }
        catch
        {
            cipherBytes = _currentBytes;
        }

        var pubParams = V2PacketZipService.ParseFlatPublicParameters(_activeRecord.ParametrosPublicosJson);
        bool isV3Local = pubParams.TryGetValue("mode", out var modeVal) &&
                         string.Equals(modeVal.Trim(), "v3-local", StringComparison.OrdinalIgnoreCase);

        string? resolvedKeyId = null;
        if (pubParams.TryGetValue("keyId", out var paramKeyId) && !string.IsNullOrWhiteSpace(paramKeyId))
        {
            resolvedKeyId = paramKeyId.Trim();
        }
        else if (!string.IsNullOrWhiteSpace(_activeRecord.LinkDescifradoRemoto))
        {
            string link = _activeRecord.LinkDescifradoRemoto.Trim();
            if (link.StartsWith("keyRef://", StringComparison.OrdinalIgnoreCase))
            {
                int lastSlash = link.LastIndexOf('/');
                if (lastSlash >= 0 && lastSlash + 1 < link.Length)
                    resolvedKeyId = link[(lastSlash + 1)..].Trim();
            }
            else if (!link.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                     !link.StartsWith("https://", StringComparison.OrdinalIgnoreCase) &&
                     !link.StartsWith("result://", StringComparison.OrdinalIgnoreCase))
            {
                resolvedKeyId = link;
            }
        }

        string existingSecret = !string.IsNullOrWhiteSpace(_activeRecord.LlaveSecretaBase64)
            ? _activeRecord.LlaveSecretaBase64
            : _txtPassphrase.Text.Trim();

        var (secretsDict, optionsDict) = BuildV2SecretsAndOptionsFromInput(algCode, existingSecret, pubParams);

        var candidatePeers = ResolveOriginPeersForActiveRecord(forceProducerFirst: isV3Local);
        var errors = new List<string>();

        try
        {
            foreach (var peer in candidatePeers)
            {
                if (!peer.IsOnline || string.IsNullOrWhiteSpace(peer.CertificatePem))
                {
                    await V2NetworkClient.PingNodeAsync(peer, customTimeoutMs: 1100);
                }

                if (peer.HasThumbprintMismatch)
                {
                    errors.Add($"{peer.NodeId} ({peer.BaseUrl}): Bloqueado por cambio de huella TOFU.");
                    continue;
                }

                if (!peer.IsOnline)
                {
                    errors.Add($"{peer.NodeId} ({peer.BaseUrl}): Nodo apagado o inalcanzable.");
                    continue;
                }

                var (success, plainBytes, resultZip, errMsg) = await V2NetworkClient.CallRemoteInverseAsync(
                    peer,
                    algCode,
                    _activeRecord.PacketId,
                    cipherBytes,
                    pubParams,
                    keyId: resolvedKeyId,
                    secretsDictionary: secretsDict,
                    options: optionsDict);

                if (success && plainBytes != null)
                {
                    ApplySuccessfulRemoteInverseResult(peer.NodeId, algCode, plainBytes, resultZip);
                    return (true, "OK");
                }

                // Si enviamos secretos locales y el emisor custodió keyId (p. ej. v3-local o keyRef), reintentar solo con keyId y secrets = null
                if (secretsDict is { Count: > 0 } && !string.IsNullOrWhiteSpace(resolvedKeyId))
                {
                    var (retryOk, retryPlain, retryZip, retryErr) = await V2NetworkClient.CallRemoteInverseAsync(
                        peer,
                        algCode,
                        _activeRecord.PacketId,
                        cipherBytes,
                        pubParams,
                        keyId: resolvedKeyId,
                        options: optionsDict);

                    if (retryOk && retryPlain != null)
                    {
                        ApplySuccessfulRemoteInverseResult(peer.NodeId, algCode, retryPlain, retryZip);
                        return (true, "OK");
                    }
                    errMsg = retryErr;
                }

                errors.Add($"{peer.NodeId} ({peer.BaseUrl}): {errMsg}");
            }
        }
        finally
        {
            RefreshNetworkGrid();
        }

        if (errors.Count > 0)
            diagnosticError = string.Join(" | ", errors);

        return (false, diagnosticError);
    }

    private void ApplySuccessfulRemoteInverseResult(
        string responderNodeId,
        string algCode,
        byte[] plainBytes,
        V2ParsedZipPacket? resultZip)
    {
        if (_activeRecord == null) return;

        _currentBytes = plainBytes;
        _isShowingEncrypted = false;
        _binarySummaryReport = null;
        _lastSavedDecryptedPath = null;

        if (!string.IsNullOrWhiteSpace(_activeRecord.Extension))
            _currentExtension = _activeRecord.Extension;
        if (!string.IsNullOrWhiteSpace(_activeRecord.NombreArchivo))
            _currentFileName = Path.GetFileName(_activeRecord.NombreArchivo);

        _hologram.TriggerDecryptAnimation(algCode);

        var hops = V2PacketZipService.TryDeserializeHops(_activeRecord.RutaSaltosJson);
        if (hops.Count == 0) hops.Add(_activeRecord.NodoRaiz);
        if (hops[^1] != responderNodeId) hops.Add(responderNodeId);

        var resultadoRecord = new RegistroCifrado
        {
            UsuarioId = _currentUser.Id,
            PacketId = resultZip?.Manifest.PacketId ?? Guid.NewGuid().ToString("D").ToLowerInvariant(),
            NombreArchivo = _currentFileName,
            Extension = _currentExtension,
            BytesCifrados = Convert.ToBase64String(plainBytes),
            AlgoritmoCodigo = algCode,
            ParametrosPublicosJson = _activeRecord.ParametrosPublicosJson,
            LlaveSecretaBase64 = string.Empty,
            LinkDescifradoRemoto = $"result://{responderNodeId}/{_activeRecord.PacketId}",
            NodoRaiz = responderNodeId,
            FirmaRaizBase64 = resultZip?.Manifest.ManifestSignatureBase64 ?? _activeRecord.FirmaRaizBase64,
            RutaSaltosJson = JsonSerializer.Serialize(hops),
            Origen = "Resultado",
            FechaOperacion = DateTime.Now
        };

        using (var db = new AppDbContext())
        {
            db.RegistrosCifrados.Add(resultadoRecord);
            db.SaveChanges();
        }

        UpdateMetadataPanel(resultadoRecord, resultZip?.SignatureValid ?? true, hasSignature: true);
        RefreshConsultasGrid();

        if (ImageViewerExtensions.Contains(_currentExtension))
            SetViewerMode("IMG");
        else
            SetViewerMode("TEXT");

        if (resultZip?.Manifest.Verification != null)
        {
            ShowVerificationBanner(resultZip.Manifest.Verification.Valid, resultZip.Manifest.Verification.Detail);
        }
        else if (algCode is "HASHSHA" or "HMACSHA256")
        {
            ShowVerificationBanner(true, $"VERIFICACIÓN VÁLIDA ({algCode}) confirmada por {responderNodeId}.");
        }
        else
        {
            HideVerificationBanner();
        }
    }

    private static bool PeerAdvertisesAlgorithm(PeerNode peer, string algCode)
    {
        if (string.IsNullOrWhiteSpace(peer.AlgorithmsJson) || string.IsNullOrWhiteSpace(algCode))
            return false;
        try
        {
            var list = JsonSerializer.Deserialize<List<string>>(peer.AlgorithmsJson);
            return list != null && list.Any(a => string.Equals(a, algCode, StringComparison.OrdinalIgnoreCase));
        }
        catch
        {
            return peer.AlgorithmsJson.Contains(algCode, StringComparison.OrdinalIgnoreCase);
        }
    }

    private PeerNode? ResolveBestPeerForAlgorithm(string algCode, string? preferredNodeId = null, bool forceProducerFirst = false)
    {
        string normAlg = algCode.Trim().ToUpperInvariant();

        if (forceProducerFirst &&
            !string.IsNullOrWhiteSpace(preferredNodeId) &&
            !string.Equals(preferredNodeId, NodeRuntimeState.CurrentNodeId, StringComparison.OrdinalIgnoreCase))
        {
            var exactProd = NodeRuntimeState.NetworkPeers.FirstOrDefault(p =>
                string.Equals(p.NodeId, preferredNodeId, StringComparison.OrdinalIgnoreCase) && !p.HasThumbprintMismatch);
            if (exactProd != null)
                return exactProd;
        }

        if (!string.IsNullOrWhiteSpace(preferredNodeId) &&
            !string.Equals(preferredNodeId, NodeRuntimeState.CurrentNodeId, StringComparison.OrdinalIgnoreCase))
        {
            var pref = NodeRuntimeState.NetworkPeers.FirstOrDefault(p =>
                string.Equals(p.NodeId, preferredNodeId, StringComparison.OrdinalIgnoreCase) && !p.HasThumbprintMismatch);
            if (pref != null && (PeerAdvertisesAlgorithm(pref, normAlg) || pref.IsOnline))
                return pref;
        }

        // 1. Pares que anuncian explícitamente el algoritmo en su /api/status o /api/algorithms (p. ej. EQ08 para HASHSHA/HMACSHA256)
        var advertisingPeers = NodeRuntimeState.NetworkPeers
            .Where(p => !string.Equals(p.NodeId, NodeRuntimeState.CurrentNodeId, StringComparison.OrdinalIgnoreCase) &&
                        !p.HasThumbprintMismatch &&
                        PeerAdvertisesAlgorithm(p, normAlg))
            .OrderByDescending(p => p.IsOnline)
            .ThenByDescending(p => p.IsConfirmed)
            .ToList();

        if (advertisingPeers.Count > 0)
            return advertisingPeers[0];

        // 2. Productor preferido aunque aún no tuviera lista de algoritmos
        if (!string.IsNullOrWhiteSpace(preferredNodeId) &&
            !string.Equals(preferredNodeId, NodeRuntimeState.CurrentNodeId, StringComparison.OrdinalIgnoreCase))
        {
            var prefFallback = NodeRuntimeState.NetworkPeers.FirstOrDefault(p =>
                string.Equals(p.NodeId, preferredNodeId, StringComparison.OrdinalIgnoreCase) && !p.HasThumbprintMismatch);
            if (prefFallback != null)
                return prefFallback;
        }

        // 3. Fallback estático de Tabla 4.1
        string staticOwner = NodeRuntimeState.GetOwnerNodeForAlgorithm(normAlg);
        if (!string.Equals(staticOwner, NodeRuntimeState.CurrentNodeId, StringComparison.OrdinalIgnoreCase))
        {
            return NodeRuntimeState.NetworkPeers.FirstOrDefault(p =>
                string.Equals(p.NodeId, staticOwner, StringComparison.OrdinalIgnoreCase));
        }

        return null;
    }

    private List<PeerNode> ResolveOriginPeersForActiveRecord(bool forceProducerFirst = false)
    {
        var result = new List<PeerNode>();
        if (_activeRecord == null) return result;

        void AddPeerIfValid(PeerNode? p)
        {
            if (p == null) return;
            if (!result.Any(x => string.Equals(x.NodeId, p.NodeId, StringComparison.OrdinalIgnoreCase) &&
                                 string.Equals(x.IpAddress, p.IpAddress, StringComparison.OrdinalIgnoreCase) &&
                                 x.Port == p.Port))
            {
                result.Add(p);
            }
        }

        if (forceProducerFirst && !string.IsNullOrWhiteSpace(_activeRecord.NodoRaiz))
        {
            var strictProducer = NodeRuntimeState.NetworkPeers.FirstOrDefault(p =>
                string.Equals(p.NodeId, _activeRecord.NodoRaiz, StringComparison.OrdinalIgnoreCase));
            AddPeerIfValid(strictProducer);
        }

        // 1. Pares vivos que anuncian explícitamente el algoritmo (detecta EQ08 cuando EQ08 anuncia HASHSHA/HMACSHA256)
        foreach (var adv in NodeRuntimeState.NetworkPeers
                     .Where(p => PeerAdvertisesAlgorithm(p, _activeRecord.AlgoritmoCodigo))
                     .OrderByDescending(p => p.IsOnline)
                     .ThenByDescending(p => p.IsConfirmed))
        {
            AddPeerIfValid(adv);
        }

        // 2. Productor / NodoRaiz del paquete
        if (!string.IsNullOrWhiteSpace(_activeRecord.NodoRaiz))
        {
            var producerPeer = NodeRuntimeState.NetworkPeers.FirstOrDefault(p =>
                string.Equals(p.NodeId, _activeRecord.NodoRaiz, StringComparison.OrdinalIgnoreCase));
            AddPeerIfValid(producerPeer);
        }

        // 3. Emisor registrado en RutaSaltosJson o en SolicitudesEntrantes (con su IP origen real si vino por red)
        var hops = V2PacketZipService.TryDeserializeHops(_activeRecord.RutaSaltosJson);
        foreach (string hopNode in hops)
        {
            var hopPeer = NodeRuntimeState.NetworkPeers.FirstOrDefault(p =>
                string.Equals(p.NodeId, hopNode, StringComparison.OrdinalIgnoreCase));
            AddPeerIfValid(hopPeer);
        }

        try
        {
            using var db = new AppDbContext();
            var sol = db.SolicitudesEntrantes
                .AsNoTracking()
                .FirstOrDefault(s => s.PacketId == _activeRecord.PacketId);

            if (sol != null && !string.IsNullOrWhiteSpace(sol.NodoOrigen))
            {
                var solPeer = NodeRuntimeState.NetworkPeers.FirstOrDefault(p =>
                    string.Equals(p.NodeId, sol.NodoOrigen, StringComparison.OrdinalIgnoreCase));

                if (solPeer != null &&
                    !string.IsNullOrWhiteSpace(sol.IpOrigen) &&
                    !sol.IpOrigen.Contains("Importación", StringComparison.OrdinalIgnoreCase) &&
                    System.Net.IPAddress.TryParse(sol.IpOrigen, out _))
                {
                    solPeer.IpAddress = sol.IpOrigen;
                }
                AddPeerIfValid(solPeer);
            }
        }
        catch { }

        // 4. Nodo dueño oficial estático de Tabla 4.1
        string ownerNodeId = NodeRuntimeState.GetOwnerNodeForAlgorithm(_activeRecord.AlgoritmoCodigo);
        var ownerPeer = NodeRuntimeState.NetworkPeers.FirstOrDefault(p =>
            string.Equals(p.NodeId, ownerNodeId, StringComparison.OrdinalIgnoreCase));
        AddPeerIfValid(ownerPeer);

        return result;
    }

    private static List<string> BuildSilentKeyRecoveryUrls(RegistroCifrado record, List<PeerNode> candidatePeers)
    {
        var urls = new List<string>();

        void AddUrl(string? u)
        {
            if (string.IsNullOrWhiteSpace(u)) return;
            if (!u.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !u.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                return;

            if (!urls.Contains(u, StringComparer.OrdinalIgnoreCase))
                urls.Add(u);
        }

        AddUrl(record.LinkDescifradoRemoto);

        foreach (var peer in candidatePeers)
        {
            AddUrl($"{peer.BaseUrl.TrimEnd('/')}/api/crypto/decrypt/{record.PacketId}");
        }

        AddUrl($"http://{NodeRuntimeState.LocalIpAddress}:{NodeRuntimeState.ApiPort}/api/crypto/decrypt/{record.PacketId}");
        return urls;
    }

    private static (Dictionary<string, string>? Secrets, Dictionary<string, string>? Options) BuildV2SecretsAndOptionsFromInput(
        string algCode,
        string? rawSecretInput,
        Dictionary<string, string> pubParams)
    {
        string normAlg = algCode.Trim().ToUpperInvariant();
        string trimmed = (rawSecretInput ?? string.Empty).Trim();

        if (normAlg == "HASHSHA")
        {
            string hAlg = pubParams.TryGetValue("hashAlgorithm", out var pubH) && !string.IsNullOrWhiteSpace(pubH)
                ? pubH.Trim()
                : "SHA-256";
            return (null, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["hashAlgorithm"] = hAlg });
        }

        if (normAlg == "HMACSHA256")
        {
            string mAlg = pubParams.TryGetValue("macAlgorithm", out var pubM) && !string.IsNullOrWhiteSpace(pubM)
                ? pubM.Trim()
                : "HMAC-SHA256";
            var opts = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["macAlgorithm"] = mAlg };
            var sec = string.IsNullOrWhiteSpace(trimmed)
                ? null
                : new Dictionary<string, string>(StringComparer.Ordinal) { ["key"] = trimmed };
            return (sec, opts);
        }

        if (normAlg is "RSA" or "ECC" or "DIFFIEHELLMAN" or "DIGITALSIG" or "QUANTUMPQC" or "LAGRANGESHAMIR" or "MILLERRABIN")
        {
            return (null, null);
        }

        if (string.IsNullOrWhiteSpace(trimmed))
            return (null, null);

        if (normAlg == "CAESAR")
        {
            string shiftStr = KeyInputParser.TryParseIntegerKey(trimmed, out int shiftVal)
                ? shiftVal.ToString(System.Globalization.CultureInfo.InvariantCulture)
                : trimmed;
            Dictionary<string, string>? opts = null;
            if (pubParams.TryGetValue("alphabet", out var alph) && !string.IsNullOrWhiteSpace(alph))
                opts = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["alphabet"] = alph.Trim() };
            return (new Dictionary<string, string>(StringComparer.Ordinal) { ["shift"] = shiftStr }, opts);
        }

        if (normAlg == "EUCLIDESAFFINE")
        {
            Dictionary<string, string>? opts = null;
            if (pubParams.TryGetValue("modulus", out var modVal) && !string.IsNullOrWhiteSpace(modVal))
                opts = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["modulus"] = modVal.Trim() };

            if (trimmed.StartsWith('{'))
            {
                try
                {
                    using var doc = JsonDocument.Parse(trimmed);
                    if (KeyInputParser.TryGetJsonInt(doc.RootElement, out int aJson, "a") &&
                        KeyInputParser.TryGetJsonInt(doc.RootElement, out int bJson, "b"))
                    {
                        return (new Dictionary<string, string>(StringComparer.Ordinal)
                        {
                            ["a"] = aJson.ToString(System.Globalization.CultureInfo.InvariantCulture),
                            ["b"] = bJson.ToString(System.Globalization.CultureInfo.InvariantCulture)
                        }, opts);
                    }
                }
                catch { }
            }

            var parts = trimmed.Split(new[] { ',', ';', ':', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2)
            {
                return (new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["a"] = parts[0].Trim(),
                    ["b"] = parts[1].Trim()
                }, opts);
            }

            if (KeyInputParser.TryDecodeBase64OrHex(trimmed, out byte[] raw) && raw.Length >= 2)
            {
                return (new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["a"] = raw[0].ToString(System.Globalization.CultureInfo.InvariantCulture),
                    ["b"] = raw[1].ToString(System.Globalization.CultureInfo.InvariantCulture)
                }, opts);
            }

            return (new Dictionary<string, string>(StringComparer.Ordinal) { ["key"] = trimmed }, opts);
        }

        if (normAlg == "FISHERYATES")
            return (new Dictionary<string, string>(StringComparer.Ordinal) { ["seed"] = trimmed }, null);

        if (normAlg == "LORENZSZ40")
            return (new Dictionary<string, string>(StringComparer.Ordinal) { ["wheelStarts"] = trimmed }, null);

        if (normAlg == "LSBSTEGO")
            return (new Dictionary<string, string>(StringComparer.Ordinal) { ["password"] = trimmed }, null);

        if (normAlg is "AESGCM" or "DES" or "TRIPLEDES" or "CHACHA20")
        {
            byte[] symBytes = ResolveRawSymmetricSecretBytesForV2(normAlg, trimmed);
            string symB64 = Convert.ToBase64String(symBytes);
            CryptographicOperations.ZeroMemory(symBytes);
            return (new Dictionary<string, string>(StringComparer.Ordinal) { ["key"] = symB64 }, null);
        }

        // VIGENERE, XORASM, DFTSPECTRAL y genéricos
        return (new Dictionary<string, string>(StringComparer.Ordinal) { ["key"] = trimmed }, null);
    }

    private static byte[] ResolveRawSymmetricSecretBytesForV2(string algCode, string secretBase64OrPassphrase)
    {
        if (KeyInputParser.TryDecodeFlexibleBase64(secretBase64OrPassphrase.Trim(), out byte[] decoded))
        {
            if (algCode == "AESGCM" && decoded.Length is 16 or 32) return decoded;
            if (algCode == "DES" && decoded.Length == 8) return decoded;
            if (algCode == "TRIPLEDES" && decoded.Length is 16 or 24) return decoded;
            if (algCode == "CHACHA20" && decoded.Length == 32) return decoded;
        }

        if (KeyInputParser.TryDecodeHex(secretBase64OrPassphrase.Trim(), out byte[] hexBytes))
        {
            if (algCode == "AESGCM" && hexBytes.Length is 16 or 32) return hexBytes;
            if (algCode == "DES" && hexBytes.Length == 8) return hexBytes;
            if (algCode == "TRIPLEDES" && hexBytes.Length is 16 or 24) return hexBytes;
            if (algCode == "CHACHA20" && hexBytes.Length == 32) return hexBytes;
        }

        byte[] utf8 = Encoding.UTF8.GetBytes(secretBase64OrPassphrase);
        return algCode switch
        {
            "AESGCM" => SHA256.HashData(utf8),
            "DES" => SHA256.HashData(utf8)[..8],
            "TRIPLEDES" => SHA256.HashData(utf8)[..24],
            "CHACHA20" => SHA256.HashData(utf8),
            _ => utf8
        };
    }

    private bool ExecuteDecryption(
        string algCode,
        byte[] cipherBytes,
        string secretKeyBase64,
        string pubJson,
        DecryptionContext? context,
        bool showErrorMessageBox,
        out string? errorDetail)
    {
        errorDetail = null;
        try
        {
            var effectiveContext = context ?? new DecryptionContext(
                PacketId: _activeRecord?.PacketId,
                OriginalFileName: _activeRecord?.NombreArchivo,
                OriginalExtension: _activeRecord?.Extension);

            var strategy = CryptoCatalog.GetStrategy(algCode);
            var res = strategy.Decrypt(cipherBytes, secretKeyBase64, pubJson, effectiveContext);

            _currentBytes = res.OutputBytes;
            _isShowingEncrypted = false;
            _binarySummaryReport = null;
            _lastSavedDecryptedPath = null;

            if (!string.IsNullOrWhiteSpace(effectiveContext.OriginalExtension))
                _currentExtension = effectiveContext.OriginalExtension;
            if (!string.IsNullOrWhiteSpace(effectiveContext.OriginalFileName))
                _currentFileName = Path.GetFileName(effectiveContext.OriginalFileName);

            if (algCode.Equals("LSBSTEGO", StringComparison.OrdinalIgnoreCase) &&
                _currentExtension.Equals(".png", StringComparison.OrdinalIgnoreCase))
            {
                _currentExtension = DetectLikelyExtension(_currentBytes);
                _currentFileName = Path.ChangeExtension(_currentFileName, _currentExtension);
            }

            if (string.IsNullOrWhiteSpace(_currentExtension))
                _currentExtension = Path.GetExtension(_currentFileName);
            if (string.IsNullOrWhiteSpace(_currentExtension))
                _currentExtension = ".bin";

            _hologram.TriggerDecryptAnimation(algCode);

            bool isPlainText = PlainTextExtensions.Contains(_currentExtension);
            bool isViewerImage = ImageViewerExtensions.Contains(_currentExtension);

            if (!isPlainText && !isViewerImage)
            {
                string autoSavedInfo = _isFromNetworkUntrusted
                    ? "Deshabilitada por seguridad para paquetes de red (usa [💾 Descargar Archivo] manualmente)."
                    : "Auto-guardado desactivado (usa [💾 Descargar Archivo]).";

                if (!_isFromNetworkUntrusted && _chkAutoDownloadBinary != null && _chkAutoDownloadBinary.Checked)
                {
                    string savedPath = SaveDecryptedBinaryAutomatically(_currentBytes, _currentFileName, _currentExtension);
                    _lastSavedDecryptedPath = savedPath;
                    autoSavedInfo = savedPath;
                }

                _binarySummaryReport =
                    $"╔══════════════════════════════════════════════════════════════════╗\r\n" +
                    $"║  ARCHIVO MULTIMEDIA / BINARIO DESCIFRADO CON ÉXITO               ║\r\n" +
                    $"╚══════════════════════════════════════════════════════════════════╝\r\n\r\n" +
                    $"• Archivo Recuperado : {_currentFileName}\r\n" +
                    $"• Extensión          : {_currentExtension}\r\n" +
                    $"• Tamaño Exacto      : {FormatFileSize(_currentBytes.Length)} ({_currentBytes.Length:N0} bytes)\r\n" +
                    $"• Algoritmo Aplicado : {algCode}\r\n" +
                    $"• Guardado Local     : {autoSavedInfo}\r\n\r\n" +
                    $"ACCIONES DISPONIBLES:\r\n" +
                    $"  1. Haz clic en [💾 Descargar Archivo] para guardarlo en la carpeta que elijas.\r\n" +
                    $"  2. Cambia a la pestaña [Hex] si deseas inspeccionar los bytes crudos.";

                SetViewerMode("TEXT");
            }
            else if (isViewerImage)
            {
                SetViewerMode("IMG");
            }
            else
            {
                SetViewerMode("TEXT");
            }

            if (algCode is "HASHSHA" or "HMACSHA256" || !res.Success)
                ShowVerificationBanner(res.Success, res.Summary);
            else
                HideVerificationBanner();

            return true;
        }
        catch (Exception ex)
        {
            errorDetail = ex.Message;
            if (showErrorMessageBox)
            {
                HologramDialog.ShowError(this, $"Error al descifrar ({algCode}):\n{ex.Message}",
                    "ModuloCrypto — Error de Descifrado");
            }
            return false;
        }
    }

    private void ExecuteDecryption(
        string algCode,
        byte[] cipherBytes,
        string secretKeyBase64,
        string pubJson,
        DecryptionContext? context = null)
    {
        ExecuteDecryption(algCode, cipherBytes, secretKeyBase64, pubJson, context, showErrorMessageBox: true, out _);
    }

    public static string SaveDecryptedBinaryAutomatically(byte[] bytes, string fileName, string extension)
    {
        string targetDir;
        try
        {
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            targetDir = Path.Combine(userProfile, "Downloads", "ModuloCrypto_Descifrados");
            Directory.CreateDirectory(targetDir);
        }
        catch
        {
            targetDir = Path.Combine(AppContext.BaseDirectory, "DecryptedFiles");
            Directory.CreateDirectory(targetDir);
        }

        string finalPath = GetUniqueFilePath(targetDir, fileName, extension);
        File.WriteAllBytes(finalPath, bytes);
        return finalPath;
    }

    private static string GetUniqueFilePath(string directory, string fileName, string extension)
    {
        string ext = string.IsNullOrWhiteSpace(extension) ? Path.GetExtension(fileName) : extension;
        if (string.IsNullOrWhiteSpace(ext)) ext = ".bin";
        if (!ext.StartsWith('.')) ext = "." + ext;

        string baseName = Path.GetFileNameWithoutExtension(fileName);
        if (string.IsNullOrWhiteSpace(baseName)) baseName = "archivo_descifrado";

        foreach (char invalid in Path.GetInvalidFileNameChars())
            baseName = baseName.Replace(invalid, '_');

        string candidate = Path.Combine(directory, baseName + ext);
        int counter = 1;
        while (File.Exists(candidate))
        {
            candidate = Path.Combine(directory, $"{baseName}_{counter}{ext}");
            counter++;
        }
        return candidate;
    }

    private static string DetectLikelyExtension(byte[] data)
    {
        if (data.Length >= 4)
        {
            if (data[0] == 0x25 && data[1] == 0x50 && data[2] == 0x44 && data[3] == 0x46) return ".pdf";
            if (data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04) return ".zip";
            if (data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47) return ".png";
            if (data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF) return ".jpg";
        }
        if (data.Length >= 12 &&
            data[4] == 0x66 && data[5] == 0x74 && data[6] == 0x79 && data[7] == 0x70)
            return ".mp4";

        bool looksUtf8Text = !data.Take(Math.Min(data.Length, 256)).Any(b => b == 0);
        return looksUtf8Text ? ".txt" : ".bin";
    }

    private static string FormatFileSize(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F2} KB";
        return $"{bytes / (1024.0 * 1024.0):F2} MB";
    }

    private async Task HandleSendZipToPeerAsync()
    {
        if (_activeRecord == null)
        {
            HologramDialog.ShowInfo(this, "Primero cifra un mensaje o archivo para generar un paquete .zip.",
                $"ModuloCrypto — {NodeRuntimeState.CurrentNodeId}");
            return;
        }

        string targetPeerId = _cmbTargetPeer.SelectedItem?.ToString()?.Split(' ')[0] ?? "";
        var peer = NodeRuntimeState.NetworkPeers.FirstOrDefault(p => p.NodeId == targetPeerId)
                   ?? NodeRuntimeState.NetworkPeers.First();

        try
        {
            byte[] cipherBytes = Convert.FromBase64String(_activeRecord.BytesCifrados);
            var hops = V2PacketZipService.TryDeserializeHops(_activeRecord.RutaSaltosJson);
            if (hops.Count == 0) hops.Add(_activeRecord.NodoRaiz);
            if (hops[^1] != peer.NodeId) hops.Add(peer.NodeId);

            if (NodeRuntimeState.IsV2)
            {
                string zipPath = !string.IsNullOrWhiteSpace(_relaySourceZipPath) &&
                                 File.Exists(_relaySourceZipPath) &&
                                 string.Equals(_activeRecord.Origen, "Recibido", StringComparison.OrdinalIgnoreCase)
                    ? V2PacketZipService.RepackageForForwarding(_relaySourceZipPath)
                    : V2PacketZipService.CreatePacketZip(_activeRecord, cipherBytes, producerNode: _activeRecord.NodoRaiz);

                var sendResult = await V2NetworkClient.SendZipPacketAsync(peer, zipPath, _activeRecord.PacketId);
                RefreshNetworkGrid();

                string msgV2 =
                    $"{sendResult.Message}\n\n" +
                    $"• Emisor (sourceNode): {NodeRuntimeState.CurrentNodeId}\n" +
                    $"• Productor (producerNode): {_activeRecord.NodoRaiz}\n" +
                    $"• Ruta: {string.Join(" → ", hops)}";
                string titleV2 = sendResult.Success ? "Envío v2.0 .ZIP Exitoso" : "Error de Envío .ZIP v2.0";
                if (sendResult.Success)
                    HologramDialog.ShowSuccess(this, msgV2, titleV2);
                else
                    HologramDialog.ShowError(this, msgV2, titleV2);
            }
            else
            {
                string zipPath = V1PacketZipService.CreatePacketZip(
                    _activeRecord,
                    cipherBytes,
                    hops,
                    rootSignatureOverride: _relayRootSignatureBase64,
                    rootCertBase64Override: _relayRootCertBase64);

                var sendResult = await V1NetworkClient.SendZipPacketAsync(peer, zipPath, _activeRecord.PacketId);
                RefreshNetworkGrid();

                string msgV1 =
                    $"{sendResult.Message}\n\n" +
                    $"• Nodo Raíz: {_activeRecord.NodoRaiz}\n" +
                    $"• Ruta Tor: {string.Join(" → ", hops)}";
                string titleV1 = sendResult.Success ? "Envío v1.0 .ZIP Exitoso" : "Error de Envío .ZIP v1.0";
                if (sendResult.Success)
                    HologramDialog.ShowSuccess(this, msgV1, titleV1);
                else
                    HologramDialog.ShowError(this, msgV1, titleV1);
            }
        }
        catch (Exception ex)
        {
            HologramDialog.ShowError(this, $"No se pudo empaquetar/enviar el .ZIP:\n{ex.Message}",
                $"ModuloCrypto — {NodeRuntimeState.CurrentNodeId}");
        }
    }

    private async Task RunPeriodicNetworkMonitorTickAsync()
    {
        if (IsDisposed) return;

        try
        {
            if (NodeRuntimeState.IsV2)
            {
                var (found, skipped) = await V2NetworkClient.ScanKnownAndImmediate24Async(
                    NodeRuntimeState.LocalIpAddress,
                    NodeRuntimeState.LocalSubnetMask,
                    startPort: 5000,
                    endPort: 5020);

                if (skipped || IsDisposed) return;

                IntegrateDiscoveredPeers(found);
                RefreshNetworkGrid();
                RefreshTargetPeerCombo();

                foreach (var peer in NodeRuntimeState.NetworkPeers.ToList())
                {
                    if (peer.IsConfirmed &&
                        peer.HasThumbprintMismatch &&
                        _alertedTofuMismatches.Add(peer.NodeId))
                    {
                        HologramDialog.ShowWarning(this,
                            $"🚨 ALERTA DE SEGURIDAD TOFU\n\n" +
                            $"El nodo fijado {peer.NodeId} ({peer.BaseUrl}) cambió su huella X.509:\n" +
                            $"• Huella fijada : {peer.PinnedThumbprintSha256}\n" +
                            $"• Nueva huella  : {peer.CertThumbprint}\n\n" +
                            $"El nodo fue bloqueado automáticamente. Reconfirma en 'Red de Nodos' solo si el cambio es legítimo.",
                            $"Alerta TOFU — {peer.NodeId}");
                    }
                }
            }
            else
            {
                foreach (var p in NodeRuntimeState.NetworkPeers.ToList())
                {
                    if (!string.Equals(p.NodeId, NodeRuntimeState.CurrentNodeId, StringComparison.OrdinalIgnoreCase))
                        await V1NetworkClient.PingNodeAsync(p, customTimeoutMs: 420, useScanClient: true);
                }

                var foundV1 = await V1NetworkClient.ScanLanSubnetAsync(
                    NodeRuntimeState.LocalIpAddress,
                    NodeRuntimeState.LocalSubnetMask,
                    startPort: 5000,
                    endPort: 5020,
                    quick24Only: true);

                if (IsDisposed) return;
                IntegrateDiscoveredPeers(foundV1);
                RefreshNetworkGrid();
                RefreshTargetPeerCombo();
            }
        }
        catch
        {
        }
    }

    private void UpdateMetadataPanel(RegistroCifrado r, bool signatureValid, bool hasSignature = true)
    {
        var hops = V2PacketZipService.TryDeserializeHops(r.RutaSaltosJson);
        if (hops.Count == 0) hops.Add(r.NodoRaiz);

        _txtMetaPacketId.Text = r.PacketId;
        _txtMetaRootNode.Text = NodeRuntimeState.IsV2
            ? $"{r.NodoRaiz} (source: {NodeRuntimeState.CurrentNodeId})"
            : r.NodoRaiz;
        _txtMetaHops.Text = string.Join("  →  ", hops);
        _txtMetaKeyRef.Text = NodeRuntimeState.IsV2
            ? $"{r.LinkDescifradoRemoto} ({r.NodoRaiz})"
            : r.LinkDescifradoRemoto;

        try
        {
            using var doc = JsonDocument.Parse(r.ParametrosPublicosJson);
            _txtMetaPublicJson.Text = JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true });
        }
        catch
        {
            _txtMetaPublicJson.Text = r.ParametrosPublicosJson;
        }

        if (!hasSignature)
        {
            _lblMetaSignatureBadge.Text = "⚠ Sin firma X.509";
            _lblMetaSignatureBadge.ForeColor = HologramTheme.Warning;
        }
        else
        {
            _lblMetaSignatureBadge.Text = signatureValid
                ? "● X.509 Activo"
                : "● X.509 Inválida";
            _lblMetaSignatureBadge.ForeColor = signatureValid ? HologramTheme.Success : HologramTheme.Danger;
        }
    }

    private void HandleIncomingPacketEvent(SolicitudEntrante solicitud)
    {
        if (IsHandleCreated && !IsDisposed)
        {
            BeginInvoke(() =>
            {
                RefreshPendingSolicitudesBadge();
                RefreshSolicitudesGrid();
                RefreshConsultasGrid();
            });
        }
    }

    private void HandlePeerChangedEvent(PeerNode peer)
    {
        if (IsHandleCreated && !IsDisposed)
        {
            BeginInvoke(() =>
            {
                RefreshNetworkGrid();
                RefreshTargetPeerCombo();
            });
        }
    }

    private void RefreshPendingSolicitudesBadge()
    {
        try
        {
            using var db = new AppDbContext();
            int pending = db.SolicitudesEntrantes
                .AsNoTracking()
                .Count(s => s.Estado == "Pendiente");
            _navSolicitudes.BadgeCount = pending;
        }
        catch
        {
            _navSolicitudes.BadgeCount = 0;
        }
    }

    private void RefreshTargetPeerCombo()
    {
        if (_cmbTargetPeer == null) return;
        int prev = _cmbTargetPeer.SelectedIndex;
        _cmbTargetPeer.Items.Clear();
        foreach (var p in NodeRuntimeState.NetworkPeers)
            _cmbTargetPeer.Items.Add($"{p.NodeId} ({p.IpAddress}:{p.Port})");
        _cmbTargetPeer.SelectedIndex = prev >= 0 && prev < _cmbTargetPeer.Items.Count ? prev : 0;
    }

    private void RefreshAllDataViews()
    {
        RefreshSolicitudesGrid();
        RefreshConsultasGrid();
        RefreshNetworkGrid();
        RefreshSettingsStats();
    }
}
