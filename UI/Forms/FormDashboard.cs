using ModuloCrypto.Core.Data;
using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using ModuloCrypto.Network;
using ModuloCrypto.Security;
using ModuloCrypto.UI.Controls;
using ModuloCrypto.UI.Theme;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
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
    private readonly string _userFullName;

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
    private Label _lblAlgDesc = null!;
    private Label _lblFileBadge = null!;
    private TextBox _txtPassphrase = null!;
    private TextBox _txtDataViewer = null!;
    private PictureBox _picImageViewer = null!;
    private NeonButton _btnModeText = null!;
    private NeonButton _btnModeHex = null!;
    private NeonButton _btnModeImg = null!;
    private CheckBox _chkAutoDownloadBinary = null!;
    private string _viewerMode = "TEXT";

    // Metadata (Tor Traceability)
    private TextBox _txtMetaPacketId = null!;
    private TextBox _txtMetaRootNode = null!;
    private Label _lblMetaSignatureBadge = null!;
    private TextBox _txtMetaHops = null!;
    private TextBox _txtMetaRemoteLink = null!;
    private TextBox _txtMetaPublicJson = null!;
    private ComboBox _cmbTargetPeer = null!;

    // Current working payload state
    private byte[] _currentBytes = Encoding.UTF8.GetBytes("Mensaje confidencial ModuloCrypto — Red Tor Bidireccional de 8 Nodos (NODO-01).");
    private string _currentFileName = "mensaje_seguro.txt";
    private string _currentExtension = ".txt";
    private RegistroCifrado? _activeRecord;
    private bool _isShowingEncrypted;
    private string? _lastSavedDecryptedPath;
    private string? _binarySummaryReport;

    // Contexto para ciclo bidireccional (Nodo Intermedio / Relay conservando rootOrigin)
    private string? _relayRootOrigin;
    private string? _relayRootSignatureBase64;
    private string? _relayRootCertBase64;
    private string? _relayOriginalHashHex;
    private List<string>? _relayHopHistory;

    public FormDashboard(Usuario currentUser)
    {
        _currentUser = currentUser;
        _currentUser.NodoAsignado = "NODO-01";
        NodeRuntimeState.CurrentNodeId = "NODO-01";

        _userFullName = string.IsNullOrWhiteSpace(currentUser.NombreCompleto)
            ? currentUser.NombreUsuario
            : currentUser.NombreCompleto;

        Text = $"ModuloCrypto — NODO-01 (:{NodeRuntimeState.ApiPort})";
        WindowState = FormWindowState.Maximized;
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(1220, 740);
        BackColor = HologramTheme.BackgroundBase;
        ForeColor = HologramTheme.TextPrimary;
        DoubleBuffered = true;

        BuildShellLayout();
        BuildDashboardCryptoView();
        BuildSolicitudesView();
        BuildConsultasView();
        BuildNetworkView();
        BuildSettingsView();

        SwitchView("dashboard");
        RefreshPendingSolicitudesBadge();
        RefreshAllDataViews();
        RenderCurrentBytesInViewer();

        NodeRuntimeState.OnPacketReceived += HandleIncomingPacketEvent;
        FormClosed += (_, _) => NodeRuntimeState.OnPacketReceived -= HandleIncomingPacketEvent;
    }

    private void BuildShellLayout()
    {
        // 1. Left Sidebar (260px exactos, fondo uniforme #151226 sin zonas blancas, borde derecho #2E284D)
        var sidebar = new Panel
        {
            Dock = DockStyle.Left,
            Width = 260,
            BackColor = HologramTheme.PanelGlass,
            Padding = new Padding(0)
        };
        sidebar.Paint += (_, e) =>
        {
            using var pen = new Pen(HologramTheme.BorderSubtle, 1f);
            e.Graphics.DrawLine(pen, sidebar.Width - 1, 0, sidebar.Width - 1, sidebar.Height);
        };

        // Top Logo Area
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
            TextRenderer.DrawText(g, "◈", new Font("Segoe UI Symbol", 15f, FontStyle.Bold), iconRect, Color.White,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);

            TextRenderer.DrawText(g, "ModuloCrypto", new Font("Segoe UI", 14f, FontStyle.Bold),
                new Rectangle(62, 18, 190, 26), HologramTheme.TextPrimary,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine);

            TextRenderer.DrawText(g, "RED TOR 8 NODOS • NODO-01", new Font("Cascadia Mono", 7.8f, FontStyle.Bold),
                new Rectangle(62, 45, 190, 18), HologramTheme.HologramCyan,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine);

            using var sepPen = new Pen(HologramTheme.BorderSubtle, 1f);
            g.DrawLine(sepPen, 16, logoPanel.Height - 1, logoPanel.Width - 16, logoPanel.Height - 1);
        };

        // Bottom-Left Logged-in Profile Card (Anclada con Dock = Bottom, muestra NombreCompleto y NODO-01)
        var profileWrap = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 152,
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
            Padding = new Padding(12)
        };
        profileCard.Paint += (_, e) =>
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            var avRect = new Rectangle(12, 14, 42, 42);
            using var avBrush = new LinearGradientBrush(avRect, HologramTheme.AccentStart, HologramTheme.HologramCyan, 135f);
            g.FillEllipse(avBrush, avRect);
            using var ringPen = new Pen(HologramTheme.HologramCyan, 1.5f);
            g.DrawEllipse(ringPen, avRect);

            string initials = BuildInitials(_userFullName);
            TextRenderer.DrawText(g, initials, new Font("Segoe UI", 11.5f, FontStyle.Bold), avRect, Color.White,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);

            using var dotGlow = new SolidBrush(Color.FromArgb(90, HologramTheme.Success));
            g.FillEllipse(dotGlow, 42, 44, 14, 14);
            using var dot = new SolidBrush(HologramTheme.Success);
            g.FillEllipse(dot, 45, 47, 8, 8);
        };

        var lblProfName = new Label
        {
            Text = _userFullName,
            Font = new Font("Segoe UI Semibold", 10f, FontStyle.Bold),
            ForeColor = HologramTheme.TextPrimary,
            Location = new Point(62, 14),
            Size = new Size(164, 22),
            BackColor = HologramTheme.PanelGlassLight,
            AutoEllipsis = true
        };
        var lblProfStatus = new Label
        {
            Text = "● Online • NODO-01",
            Font = new Font("Cascadia Mono", 8.2f, FontStyle.Bold),
            ForeColor = HologramTheme.Success,
            Location = new Point(62, 38),
            Size = new Size(164, 20),
            BackColor = HologramTheme.PanelGlassLight
        };
        var btnLogout = new NeonButton
        {
            Text = "Cerrar Sesión",
            Variant = NeonButtonVariant.Secondary,
            Location = new Point(12, 78),
            Size = new Size(210, 36),
            CornerRadius = 9,
            Font = new Font("Segoe UI Semibold", 9.2f, FontStyle.Bold)
        };
        btnLogout.Click += (_, _) =>
        {
            SignOutRequested = true;
            Close();
        };

        profileCard.Controls.AddRange(new Control[] { lblProfName, lblProfStatus, btnLogout });
        profileWrap.Controls.Add(profileCard);

        // Navigation Menu Stack (Fondo uniforme #151226, espaciado vertical uniforme de 12px entre botones)
        var navContainer = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = HologramTheme.PanelGlass
        };

        var navItems = new (string key, string glyph, string text)[]
        {
            ("dashboard", "◆", "Dashboard / Cifrado"),
            ("inbox",     "✉", "Solicitudes"),
            ("history",   "▤", "Consultas / Historial"),
            ("network",   "◎", "Red de Nodos (IP)"),
            ("settings",  "⚙", "Ajustes")
        };

        int curY = 16;
        foreach (var item in navItems)
        {
            var btn = CreateNavButton(item.key, item.glyph, item.text);
            btn.Location = new Point(12, curY);
            btn.Size = new Size(236, 46);
            navContainer.Controls.Add(btn);
            curY += 46 + 12;
        }
        _navSolicitudes = _navButtons["inbox"];

        sidebar.Controls.Add(navContainer);
        sidebar.Controls.Add(profileWrap);
        sidebar.Controls.Add(logoPanel);

        // 2. Right Main Container (Topbar + ViewHost)
        var mainRight = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = HologramTheme.BackgroundBase
        };

        var topbar = new Panel
        {
            Dock = DockStyle.Top,
            Height = 80,
            BackColor = HologramTheme.PanelGlass,
            Padding = new Padding(22, 12, 22, 10)
        };
        topbar.Paint += (_, e) =>
        {
            using var pen = new Pen(HologramTheme.BorderSubtle, 1f);
            e.Graphics.DrawLine(pen, 0, topbar.Height - 1, topbar.Width, topbar.Height - 1);
        };

        var greetingPanel = new Panel
        {
            Dock = DockStyle.Left,
            Width = 340,
            BackColor = HologramTheme.PanelGlass
        };
        var lblWelcome = new Label
        {
            Text = $"Bienvenido, {_userFullName}",
            Font = new Font("Segoe UI", 14.5f, FontStyle.Bold),
            ForeColor = HologramTheme.TextPrimary,
            Location = new Point(0, 4),
            Size = new Size(336, 30),
            BackColor = HologramTheme.PanelGlass,
            AutoEllipsis = false
        };
        var lblSubWelcome = new Label
        {
            Text = "Nodo activo: NODO-01 • Estado: Operativo",
            Font = new Font("Segoe UI Semibold", 9.2f),
            ForeColor = HologramTheme.HologramCyan,
            Location = new Point(0, 36),
            Size = new Size(336, 22),
            BackColor = HologramTheme.PanelGlass,
            AutoEllipsis = false
        };
        greetingPanel.Controls.Add(lblWelcome);
        greetingPanel.Controls.Add(lblSubWelcome);

        var algPanel = new Panel
        {
            Dock = DockStyle.Right,
            Width = 320,
            BackColor = HologramTheme.PanelGlass
        };
        var lblAlgCap = new Label
        {
            Text = "ALGORITMO ACTIVO (21 OFICIALES)",
            Font = new Font("Cascadia Mono", 8.2f, FontStyle.Bold),
            ForeColor = HologramTheme.HologramViolet,
            Location = new Point(4, 2),
            Size = new Size(312, 18),
            BackColor = HologramTheme.PanelGlass,
            AutoEllipsis = false
        };
        _cmbAlgorithm = new ComboBox
        {
            Location = new Point(4, 23),
            Size = new Size(312, 32),
            Font = new Font("Cascadia Mono", 9.2f, FontStyle.Bold)
        };
        HologramTheme.StyleComboBox(_cmbAlgorithm, HologramTheme.HologramCyan);
        foreach (var alg in CryptoCatalog.OfficialAlgorithms)
            _cmbAlgorithm.Items.Add(alg);
        _cmbAlgorithm.SelectedIndex = 0;
        _cmbAlgorithm.SelectedIndexChanged += (_, _) => UpdateSelectedAlgorithmHud();
        algPanel.Controls.Add(lblAlgCap);
        algPanel.Controls.Add(_cmbAlgorithm);

        var pillsFlow = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            Padding = new Padding(10, 14, 10, 0),
            BackColor = HologramTheme.PanelGlass
        };
        _pillApi = new StatusPill
        {
            Text = NodeRuntimeState.ApiOnline ? $"API: Online :{NodeRuntimeState.ApiPort}" : "API: Offline",
            IsActive = NodeRuntimeState.ApiOnline,
            Margin = new Padding(4, 0, 8, 0)
        };
        _pillSqlite = new StatusPill
        {
            Text = NodeRuntimeState.SqliteConnected ? "SQLite: Conectado" : "SQLite: Error",
            IsActive = NodeRuntimeState.SqliteConnected,
            Margin = new Padding(0, 0, 8, 0)
        };
        _pillCert = new StatusPill
        {
            Text = NodeRuntimeState.CertificateActive ? "Certificado X.509: Activo" : "X.509: Inactivo",
            IsActive = NodeRuntimeState.CertificateActive,
            Margin = new Padding(0, 0, 4, 0)
        };
        pillsFlow.Controls.AddRange(new Control[] { _pillApi, _pillSqlite, _pillCert });

        topbar.Controls.Add(pillsFlow);
        topbar.Controls.Add(algPanel);
        topbar.Controls.Add(greetingPanel);

        _viewHost = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = HologramTheme.BackgroundBase,
            Padding = new Padding(18)
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

        if (key == "inbox") RefreshSolicitudesGrid();
        else if (key == "history") RefreshConsultasGrid();
        else if (key == "network") RefreshNetworkGrid();
        else if (key == "settings") RefreshSettingsStats();
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

        // === COLUMNA IZQUIERDA / CENTRO: HOLOGRAMA 3D BINARIO + CONTROLES PRINCIPALES ===
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
            StatusSubtitle = "NODO-01 • Cubo Binario 3D en Reposo"
        };

        _lblAlgDesc = new Label
        {
            Dock = DockStyle.Bottom,
            Height = 36,
            Font = new Font("Segoe UI", 8.8f),
            ForeColor = HologramTheme.TextSecondary,
            TextAlign = ContentAlignment.MiddleCenter,
            BackColor = HologramTheme.PanelGlass
        };

        holoCard.Controls.Add(_hologram);
        holoCard.Controls.Add(_lblAlgDesc);

        var actionCard = new GlassPanel
        {
            Dock = DockStyle.Bottom,
            Height = 152,
            CornerRadius = 16,
            Padding = new Padding(12, 10, 12, 10)
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
        actionGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
        actionGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 46));
        actionGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 46));

        _txtPassphrase = HologramTheme.CreateDarkTextBox();
        _txtPassphrase.Dock = DockStyle.Fill;
        _txtPassphrase.PlaceholderText = "Clave opcional (o auto-generar llave criptográfica)";
        _txtPassphrase.Margin = new Padding(3, 4, 6, 4);
        actionGrid.Controls.Add(_txtPassphrase, 0, 0);
        actionGrid.SetColumnSpan(_txtPassphrase, 2);

        _cmbTargetPeer = new ComboBox
        {
            Dock = DockStyle.Fill,
            Font = new Font("Cascadia Mono", 8.5f, FontStyle.Bold),
            Margin = new Padding(3, 4, 3, 4)
        };
        HologramTheme.StyleComboBox(_cmbTargetPeer, HologramTheme.HologramCyan);
        RefreshTargetPeerCombo();
        actionGrid.Controls.Add(_cmbTargetPeer, 2, 0);

        var btnLoadFile = new NeonButton
        {
            Text = "📂 Cargar Archivo",
            Variant = NeonButtonVariant.Secondary,
            Dock = DockStyle.Fill,
            Margin = new Padding(3),
            Font = new Font("Segoe UI Semibold", 9f, FontStyle.Bold)
        };
        btnLoadFile.Click += (_, _) => HandleLoadFile();

        var btnEncrypt = new NeonButton
        {
            Text = "🔒 Cifrar (Nodo Raíz)",
            Variant = NeonButtonVariant.Primary,
            Dock = DockStyle.Fill,
            Margin = new Padding(3),
            Font = new Font("Segoe UI Semibold", 9f, FontStyle.Bold)
        };
        btnEncrypt.Click += (_, _) => HandleEncryptAction(asIntermediateHop: false);

        var btnRelayEncrypt = new NeonButton
        {
            Text = "🔁 Re-Cifrar Salto Tor",
            Variant = NeonButtonVariant.Cyan,
            Dock = DockStyle.Fill,
            Margin = new Padding(3),
            Font = new Font("Segoe UI Semibold", 9f, FontStyle.Bold)
        };
        btnRelayEncrypt.Click += (_, _) => HandleEncryptAction(asIntermediateHop: true);

        actionGrid.Controls.Add(btnLoadFile, 0, 1);
        actionGrid.Controls.Add(btnEncrypt, 1, 1);
        actionGrid.Controls.Add(btnRelayEncrypt, 2, 1);

        var btnDecryptLocal = new NeonButton
        {
            Text = "🔓 Descifrar Local",
            Variant = NeonButtonVariant.Success,
            Dock = DockStyle.Fill,
            Margin = new Padding(3),
            Font = new Font("Segoe UI Semibold", 9f, FontStyle.Bold)
        };
        btnDecryptLocal.Click += (_, _) => HandleDecryptLocalAction();

        var btnDecryptRemote = new NeonButton
        {
            Text = "🌐 Descifrar Remoto",
            Variant = NeonButtonVariant.Secondary,
            Dock = DockStyle.Fill,
            Margin = new Padding(3),
            Font = new Font("Segoe UI Semibold", 9f, FontStyle.Bold)
        };
        btnDecryptRemote.Click += async (_, _) => await HandleDecryptRemoteActionAsync();

        var btnSendZip = new NeonButton
        {
            Text = "🚀 Enviar .ZIP a IP",
            Variant = NeonButtonVariant.Primary,
            Dock = DockStyle.Fill,
            Margin = new Padding(3),
            Font = new Font("Segoe UI Semibold", 9f, FontStyle.Bold)
        };
        btnSendZip.Click += async (_, _) => await HandleSendZipToPeerAsync();

        actionGrid.Controls.Add(btnDecryptLocal, 0, 2);
        actionGrid.Controls.Add(btnDecryptRemote, 1, 2);
        actionGrid.Controls.Add(btnSendZip, 2, 2);

        actionCard.Controls.Add(actionGrid);

        var spacer = new Panel { Dock = DockStyle.Bottom, Height = 12, BackColor = HologramTheme.BackgroundBase };
        leftCol.Controls.Add(holoCard);
        leftCol.Controls.Add(spacer);
        leftCol.Controls.Add(actionCard);

        // === COLUMNA DERECHA: VISOR (TEXTO/HEX/IMAGEN + DESCARGA/APERTURA) + TRAZABILIDAD TOR ===
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

        // Top Right Card: Visor Texto / Hex / Imagen + Barra Multimedia/Binarios
        var viewerCard = new GlassPanel
        {
            Dock = DockStyle.Fill,
            CornerRadius = 16,
            Padding = new Padding(14),
            Margin = new Padding(0, 0, 0, 12)
        };

        var viewerHeader = new Panel { Dock = DockStyle.Top, Height = 34, BackColor = HologramTheme.PanelGlass };
        _lblFileBadge = new Label
        {
            Text = "VISOR DE CARGA • mensaje_seguro.txt",
            Font = new Font("Segoe UI Semibold", 9.4f, FontStyle.Bold),
            ForeColor = HologramTheme.HologramCyan,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            BackColor = HologramTheme.PanelGlass,
            AutoEllipsis = true
        };

        var modeButtons = new FlowLayoutPanel
        {
            Dock = DockStyle.Right,
            Width = 228,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            BackColor = HologramTheme.PanelGlass
        };
        _btnModeText = new NeonButton { Text = "Texto", Size = new Size(70, 28), CornerRadius = 8, Variant = NeonButtonVariant.Primary, Font = new Font("Segoe UI Semibold", 8.3f) };
        _btnModeHex = new NeonButton { Text = "Hex", Size = new Size(66, 28), CornerRadius = 8, Variant = NeonButtonVariant.Secondary, Font = new Font("Segoe UI Semibold", 8.3f) };
        _btnModeImg = new NeonButton { Text = "Imagen", Size = new Size(74, 28), CornerRadius = 8, Variant = NeonButtonVariant.Secondary, Font = new Font("Segoe UI Semibold", 8.3f) };

        _btnModeText.Click += (_, _) => { _binarySummaryReport = null; SetViewerMode("TEXT"); };
        _btnModeHex.Click += (_, _) => { SetViewerMode("HEX"); };
        _btnModeImg.Click += (_, _) => { SetViewerMode("IMG"); };
        modeButtons.Controls.AddRange(new Control[] { _btnModeText, _btnModeHex, _btnModeImg });

        viewerHeader.Controls.Add(_lblFileBadge);
        viewerHeader.Controls.Add(modeButtons);

        // Segunda barra del Visor: Botones Descargar Archivo, Abrir Archivo y CheckBox Auto-descarga
        var fileActionsBar = new Panel
        {
            Dock = DockStyle.Top,
            Height = 38,
            Padding = new Padding(0, 4, 0, 2),
            BackColor = HologramTheme.PanelGlass
        };

        var btnDownloadFile = new NeonButton
        {
            Text = "💾 Descargar Archivo",
            Variant = NeonButtonVariant.Cyan,
            Location = new Point(0, 4),
            Size = new Size(156, 30),
            CornerRadius = 8,
            Font = new Font("Segoe UI Semibold", 8.5f, FontStyle.Bold)
        };
        btnDownloadFile.Click += (_, _) => HandleDownloadCurrentFile();

        var btnOpenFile = new NeonButton
        {
            Text = "▶ Abrir Archivo",
            Variant = NeonButtonVariant.Success,
            Location = new Point(164, 4),
            Size = new Size(134, 30),
            CornerRadius = 8,
            Font = new Font("Segoe UI Semibold", 8.5f, FontStyle.Bold)
        };
        btnOpenFile.Click += (_, _) => HandleOpenCurrentFileInWindows();

        _chkAutoDownloadBinary = new CheckBox
        {
            Text = "Auto-descargar multimedia/binarios al descifrar",
            Checked = true,
            AutoSize = true,
            Location = new Point(308, 9),
            Font = new Font("Segoe UI", 8.5f),
            ForeColor = HologramTheme.HologramViolet,
            BackColor = HologramTheme.PanelGlass
        };

        fileActionsBar.Controls.AddRange(new Control[] { btnDownloadFile, btnOpenFile, _chkAutoDownloadBinary });

        var viewerBody = new Panel { Dock = DockStyle.Fill, Padding = new Padding(0, 6, 0, 0), BackColor = HologramTheme.PanelGlass };
        _txtDataViewer = HologramTheme.CreateDarkTextBox(multiline: true, readOnly: false, mono: true);
        _txtDataViewer.Dock = DockStyle.Fill;
        _txtDataViewer.TextChanged += (_, _) =>
        {
            if (_viewerMode == "TEXT" && !_isShowingEncrypted && _binarySummaryReport == null && _txtDataViewer.Focused)
            {
                _currentBytes = Encoding.UTF8.GetBytes(_txtDataViewer.Text);
                _currentFileName = "mensaje_manual.txt";
                _currentExtension = ".txt";
                _lastSavedDecryptedPath = null;
                _lblFileBadge.Text = $"VISOR DE CARGA • {_currentFileName} ({_currentBytes.Length} B)";
            }
        };

        _picImageViewer = new PictureBox
        {
            Dock = DockStyle.Fill,
            SizeMode = PictureBoxSizeMode.Zoom,
            BackColor = HologramTheme.PanelInput,
            Visible = false
        };

        viewerBody.Controls.Add(_txtDataViewer);
        viewerBody.Controls.Add(_picImageViewer);

        viewerCard.Controls.Add(viewerBody);
        viewerCard.Controls.Add(fileActionsBar);
        viewerCard.Controls.Add(viewerHeader);

        // Bottom Right Card: TRAZABILIDAD TOR • METADATOS
        var metaCard = new GlassPanel
        {
            Dock = DockStyle.Fill,
            CornerRadius = 16,
            Padding = new Padding(14)
        };

        var metaHeader = new Panel { Dock = DockStyle.Top, Height = 30, BackColor = HologramTheme.PanelGlass };
        var lblMetaTitle = new Label
        {
            Text = "TRAZABILIDAD TOR • METADATOS",
            Font = new Font("Segoe UI Semibold", 9.8f, FontStyle.Bold),
            ForeColor = HologramTheme.HologramViolet,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            BackColor = HologramTheme.PanelGlass,
            AutoEllipsis = false
        };
        _lblMetaSignatureBadge = new Label
        {
            Text = "● X.509 Listo (NODO-01)",
            Font = new Font("Cascadia Mono", 8.4f, FontStyle.Bold),
            ForeColor = HologramTheme.HologramCyan,
            Dock = DockStyle.Right,
            Width = 235,
            TextAlign = ContentAlignment.MiddleRight,
            BackColor = HologramTheme.PanelGlass
        };
        metaHeader.Controls.Add(lblMetaTitle);
        metaHeader.Controls.Add(_lblMetaSignatureBadge);

        var metaGrid = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 5,
            Padding = new Padding(0, 6, 0, 0),
            BackColor = HologramTheme.PanelGlass
        };
        metaGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 152));
        metaGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        metaGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        metaGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        metaGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        metaGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        metaGrid.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        _txtMetaPacketId = AddMetaRow(metaGrid, 0, "Packet ID (UUID):", "---");
        _txtMetaRootNode = AddMetaRow(metaGrid, 1, "Nodo Raíz (Origen):", "NODO-01");
        _txtMetaHops = AddMetaRow(metaGrid, 2, "Ruta Saltos Tor:", "NODO-01");
        _txtMetaRemoteLink = AddMetaRow(metaGrid, 3, "Link Remoto:", "http://...");

        var lblPub = new Label
        {
            Text = "Parámetros JSON:",
            Font = new Font("Segoe UI Semibold", 8.6f),
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
            Font = new Font("Segoe UI Semibold", 8.6f),
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
            _lblAlgDesc.Text = $"[{info.Category}]  {info.Description}";
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
        _lblFileBadge.Text = $"VISOR • {_currentFileName} ({FormatFileSize(_currentBytes.Length)})" +
                             (_isShowingEncrypted ? " [CIFRADO]" : " [PLANO]");

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
        _lastSavedDecryptedPath = ofd.FileName;
        _binarySummaryReport = null;

        ClearRelayContext();

        _hologram.SetIdle($"Archivo cargado en NODO-01: {_currentFileName} ({FormatFileSize(_currentBytes.Length)})");

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
            MessageBox.Show(this, "No hay bytes activos en el visor para guardar.", "ModuloCrypto", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        string suggestedName = string.IsNullOrWhiteSpace(_currentFileName) ? $"archivo{_currentExtension}" : _currentFileName;
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
        MessageBox.Show(this, $"Archivo guardado correctamente:\n{sfd.FileName}\nTamaño: {FormatFileSize(_currentBytes.Length)}",
            "Archivo Guardado", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void HandleOpenCurrentFileInWindows()
    {
        if (_currentBytes == null || _currentBytes.Length == 0)
        {
            MessageBox.Show(this, "No hay ningún archivo cargado o descifrado para abrir.", "ModuloCrypto", MessageBoxButtons.OK, MessageBoxIcon.Information);
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
            MessageBox.Show(this, $"No se pudo abrir el archivo con el visor de Windows:\n{ex.Message}",
                "ModuloCrypto", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void ClearRelayContext()
    {
        _relayRootOrigin = null;
        _relayRootSignatureBase64 = null;
        _relayRootCertBase64 = null;
        _relayOriginalHashHex = null;
        _relayHopHistory = null;
    }

    private void HandleEncryptAction(bool asIntermediateHop)
    {
        if (_cmbAlgorithm.SelectedItem is not CryptoAlgorithmInfo algInfo) return;

        try
        {
            if (_viewerMode == "TEXT" && !_isShowingEncrypted && _binarySummaryReport == null)
                _currentBytes = Encoding.UTF8.GetBytes(_txtDataViewer.Text);

            string origFileNameBeforeEncrypt = _currentFileName;
            string origExtensionBeforeEncrypt = _currentExtension;

            var strategy = CryptoCatalog.GetStrategy(algInfo.Code);
            var result = strategy.Encrypt(_currentBytes, _txtPassphrase.Text);

            // Conservar nombre y extensión original en ParametrosPublicosJson (vital para LSBSTEGO y archivos multimedia/binarios)
            string enrichedPubJson = EnrichPublicParametersWithOriginalFileMeta(
                result.PublicParametersJson,
                origFileNameBeforeEncrypt,
                origExtensionBeforeEncrypt);

            string packetId = Guid.NewGuid().ToString();
            string remoteLink = NodeRuntimeState.BuildRemoteDecryptUrl(packetId);

            string rootOrigin;
            string rootSignature;
            List<string> hops;

            if (asIntermediateHop && !string.IsNullOrWhiteSpace(_relayRootOrigin))
            {
                rootOrigin = _relayRootOrigin!;
                rootSignature = _relayRootSignatureBase64 ?? NodeCertificateService.SignPayload(result.OutputBytes);
                hops = _relayHopHistory != null ? new List<string>(_relayHopHistory) : new List<string> { rootOrigin };
                if (hops.Count == 0 || hops[^1] != "NODO-01")
                    hops.Add("NODO-01");
            }
            else
            {
                ClearRelayContext();
                rootOrigin = "NODO-01";
                string payloadHashHex = Convert.ToHexString(SHA256.HashData(result.OutputBytes));
                _relayOriginalHashHex = payloadHashHex;
                _relayRootCertBase64 = NodeCertificateService.ExportPublicCertBase64();
                rootSignature = NodeCertificateService.SignPayload(Encoding.ASCII.GetBytes(payloadHashHex));
                hops = new List<string> { "NODO-01" };
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
                ParametrosPublicosJson = enrichedPubJson,
                LlaveSecretaBase64 = result.SecretKeyBase64,
                LinkDescifradoRemoto = remoteLink,
                NodoRaiz = rootOrigin,
                FirmaRaizBase64 = rootSignature,
                RutaSaltosJson = JsonSerializer.Serialize(hops),
                Origen = asIntermediateHop && rootOrigin != "NODO-01" ? "Relay" : "Local",
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
            MessageBox.Show(this, $"Error durante el cifrado ({algInfo.Code}):\n{ex.Message}",
                "ModuloCrypto — Error de Cifrado", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private static string EnrichPublicParametersWithOriginalFileMeta(string pubJson, string origFileName, string origExt)
    {
        try
        {
            var node = JsonNode.Parse(string.IsNullOrWhiteSpace(pubJson) ? "{}" : pubJson) as JsonObject ?? new JsonObject();
            if (!string.IsNullOrWhiteSpace(origFileName))
                node["originalFileName"] = origFileName;
            if (!string.IsNullOrWhiteSpace(origExt))
                node["originalExtension"] = origExt;
            return node.ToJsonString();
        }
        catch
        {
            return pubJson;
        }
    }

    private static (string? OrigName, string? OrigExt) ExtractOriginalFileMetaFromJson(string? pubJson)
    {
        if (string.IsNullOrWhiteSpace(pubJson)) return (null, null);
        try
        {
            using var doc = JsonDocument.Parse(pubJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return (null, null);

            string? name = doc.RootElement.TryGetProperty("originalFileName", out var nProp) && nProp.ValueKind == JsonValueKind.String
                ? nProp.GetString()
                : null;
            string? ext = doc.RootElement.TryGetProperty("originalExtension", out var eProp) && eProp.ValueKind == JsonValueKind.String
                ? eProp.GetString()
                : null;
            return (name, ext);
        }
        catch
        {
            return (null, null);
        }
    }

    private void HandleDecryptLocalAction()
    {
        if (_activeRecord == null)
        {
            MessageBox.Show(this, "Primero cifra un paquete o carga un registro desde Consultas / Solicitudes.",
                "ModuloCrypto — NODO-01", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        string keyToUse = string.IsNullOrWhiteSpace(_activeRecord.LlaveSecretaBase64)
            ? _txtPassphrase.Text
            : _activeRecord.LlaveSecretaBase64;

        ExecuteDecryption(_activeRecord.AlgoritmoCodigo, _currentBytes, keyToUse, _activeRecord.ParametrosPublicosJson);
    }

    private async Task HandleDecryptRemoteActionAsync()
    {
        string url = _txtMetaRemoteLink.Text.Trim();
        if (string.IsNullOrWhiteSpace(url) || !url.StartsWith("http", StringComparison.OrdinalIgnoreCase))
        {
            MessageBox.Show(this, "No hay un Link de Descifrado Remoto válido en los metadatos activos.",
                "ModuloCrypto — NODO-01", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        _hologram.StatusSubtitle = $"Consultando llave remota en {url}...";
        var resp = await NodeNetworkClient.RequestRemoteKeyAsync(url);
        if (!resp.Success)
        {
            MessageBox.Show(this, $"Descifrado remoto fallido:\n{resp.Message}",
                "ModuloCrypto — Descifrado Remoto", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        ExecuteDecryption(resp.AlgoritmoCodigo, _currentBytes, resp.LlaveSecretaBase64, resp.ParametrosPublicosJson);
    }

    private void ExecuteDecryption(string algCode, byte[] cipherBytes, string secretKeyBase64, string pubJson)
    {
        try
        {
            var strategy = CryptoCatalog.GetStrategy(algCode);
            var res = strategy.Decrypt(cipherBytes, secretKeyBase64, pubJson);

            _currentBytes = res.OutputBytes;
            _isShowingEncrypted = false;
            _binarySummaryReport = null;
            _lastSavedDecryptedPath = null;

            // Restaurar nombre y extensión original (especialmente útil tras LSBSTEGO o paquetes recibidos)
            var (origName, origExt) = ExtractOriginalFileMetaFromJson(pubJson);
            if (!string.IsNullOrWhiteSpace(origExt))
                _currentExtension = origExt;
            if (!string.IsNullOrWhiteSpace(origName))
                _currentFileName = origName;
            else if (algCode.Equals("LSBSTEGO", StringComparison.OrdinalIgnoreCase) &&
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

            if (_activeRecord != null)
            {
                string hopsStr = string.Join(" → ", PacketZipService.TryDeserializeHops(_activeRecord.RutaSaltosJson));
                _hologram.StatusSubtitle = $"DESCIFRADO EN NODO-01 • Origen Raíz: {_activeRecord.NodoRaiz} • Ruta: {hopsStr}";
            }

            bool isPlainText = PlainTextExtensions.Contains(_currentExtension);
            bool isViewerImage = ImageViewerExtensions.Contains(_currentExtension);

            if (!isPlainText && !isViewerImage)
            {
                // Archivo multimedia o binario (.mp4, .pdf, .docx, .xlsx, .mp3, .zip, etc.)
                string autoSavedInfo = "Auto-descarga desactivada (usa [💾 Descargar Archivo] o [▶ Abrir Archivo]).";

                if (_chkAutoDownloadBinary != null && _chkAutoDownloadBinary.Checked)
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
                    $"• Descarga Automática: {autoSavedInfo}\r\n\r\n" +
                    $"ACCIONES DISPONIBLES:\r\n" +
                    $"  1. Haz clic en [▶ Abrir Archivo] para reproducirlo o visualizarlo con Windows.\r\n" +
                    $"  2. Haz clic en [💾 Descargar Archivo] para guardarlo en otra carpeta.\r\n" +
                    $"  3. Cambia a la pestaña [Hex] si deseas inspeccionar los bytes crudos.";

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
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Error al descifrar ({algCode}):\n{ex.Message}",
                "ModuloCrypto — Error de Descifrado", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
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
            MessageBox.Show(this, "Primero cifra un mensaje o archivo para generar un paquete .zip.",
                "ModuloCrypto — NODO-01", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        string targetPeerId = _cmbTargetPeer.SelectedItem?.ToString()?.Split(' ')[0] ?? "NODO-02";
        var peer = NodeRuntimeState.NetworkPeers.FirstOrDefault(p => p.NodeId == targetPeerId)
                   ?? NodeRuntimeState.NetworkPeers.First();

        try
        {
            byte[] cipherBytes = Convert.FromBase64String(_activeRecord.BytesCifrados);
            var hops = PacketZipService.TryDeserializeHops(_activeRecord.RutaSaltosJson);
            if (hops.Count == 0) hops.Add(_activeRecord.NodoRaiz);
            if (hops[^1] != peer.NodeId) hops.Add(peer.NodeId);

            string zipPath = PacketZipService.CreatePacketZip(
                _activeRecord,
                cipherBytes,
                hops,
                preservedRootCertBase64: _relayRootCertBase64,
                preservedOriginalHashHex: _relayOriginalHashHex);

            var sendResult = await NodeNetworkClient.SendZipPacketAsync(peer, zipPath, _activeRecord.PacketId);
            RefreshNetworkGrid();

            MessageBox.Show(this,
                $"{sendResult.Message}\n\n" +
                $"• Nodo Raíz (rootOrigin): {_activeRecord.NodoRaiz}\n" +
                $"• Protocolo Destino: {peer.ProtocolType}\n" +
                $"• Ruta de Saltos (hopHistory): {string.Join(" → ", hops)}",
                sendResult.Success ? "Envío Tor .ZIP Exitoso" : "Error de Envío .ZIP",
                MessageBoxButtons.OK,
                sendResult.Success ? MessageBoxIcon.Information : MessageBoxIcon.Error);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"No se pudo empaquetar/enviar el .ZIP:\n{ex.Message}",
                "ModuloCrypto — NODO-01", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void UpdateMetadataPanel(RegistroCifrado r, bool signatureValid, bool hasSignature = true)
    {
        var hops = PacketZipService.TryDeserializeHops(r.RutaSaltosJson);
        if (hops.Count == 0) hops.Add(r.NodoRaiz);

        _txtMetaPacketId.Text = r.PacketId;
        _txtMetaRootNode.Text = $"{r.NodoRaiz}  (Originador del Circuito)";
        _txtMetaHops.Text = string.Join("  →  ", hops);
        _txtMetaRemoteLink.Text = string.IsNullOrWhiteSpace(r.LinkDescifradoRemoto)
            ? "(Paquete externo — Clave local)"
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
            _lblMetaSignatureBadge.Text = "⚠ Sin firma X.509 (Modo Tolerante)";
            _lblMetaSignatureBadge.ForeColor = HologramTheme.Warning;
        }
        else
        {
            _lblMetaSignatureBadge.Text = signatureValid
                ? $"● Firma Raíz ({r.NodoRaiz}) VÁLIDA"
                : $"● Firma Raíz ({r.NodoRaiz}) INVÁLIDA";
            _lblMetaSignatureBadge.ForeColor = signatureValid ? HologramTheme.Success : HologramTheme.Danger;
        }
    }

    private void HandleIncomingPacketEvent(SolicitudEntrante solicitud)
    {
        if (IsDisposed) return;
        BeginInvoke(() =>
        {
            RefreshPendingSolicitudesBadge();
            RefreshSolicitudesGrid();
            _hologram.StatusSubtitle = $"Paquete .ZIP recibido en NODO-01 desde {solicitud.NodoOrigen} ({solicitud.AlgoritmoCodigo})";
        });
    }

    private void RefreshPendingSolicitudesBadge()
    {
        try
        {
            using var db = new AppDbContext();
            int pending = db.SolicitudesEntrantes.Count(s => s.Estado == "Pendiente");
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
