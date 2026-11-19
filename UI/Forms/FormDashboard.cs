using ModuloCrypto.Core.Data;
using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using ModuloCrypto.Network;
using ModuloCrypto.Security;
using ModuloCrypto.UI.Controls;
using ModuloCrypto.UI.Theme;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Text;
using System.Text.Json;
using System.Windows.Forms;

namespace ModuloCrypto.UI.Forms;

public partial class FormDashboard : Form
{
    public bool SignOutRequested { get; private set; }

    private readonly Usuario _currentUser;

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
    private byte[] _currentBytes = Encoding.UTF8.GetBytes("Mensaje confidencial ModuloCrypto — Red Tor de 8 Nodos.");
    private string _currentFileName = "mensaje_seguro.txt";
    private string _currentExtension = ".txt";
    private RegistroCifrado? _activeRecord;
    private bool _isShowingEncrypted;

    public FormDashboard(Usuario currentUser)
    {
        _currentUser = currentUser;
        NodeRuntimeState.CurrentNodeId = currentUser.NodoAsignado;

        Text = $"ModuloCrypto — {currentUser.NodoAsignado} ({currentUser.NombreUsuario})";
        WindowState = FormWindowState.Maximized;
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(1200, 740);
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
        // 1. Left Sidebar (260px)
        var sidebar = new Panel
        {
            Dock = DockStyle.Left,
            Width = 264,
            BackColor = Color.FromArgb(16, 13, 30),
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
            Height = 88,
            Padding = new Padding(18, 16, 16, 10),
            BackColor = Color.Transparent
        };
        logoPanel.Paint += (_, e) =>
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            var iconRect = new Rectangle(18, 22, 38, 38);
            using var path = HologramTheme.CreateRoundedPath(iconRect, 11);
            using var brush = new LinearGradientBrush(iconRect, HologramTheme.AccentStart, HologramTheme.HologramCyan, 135f);
            g.FillPath(brush, path);
            TextRenderer.DrawText(g, "◈", new Font("Segoe UI Symbol", 16f, FontStyle.Bold), iconRect, Color.White,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);

            TextRenderer.DrawText(g, "ModuloCrypto", new Font("Segoe UI", 14.5f, FontStyle.Bold),
                new Rectangle(64, 19, 185, 26), HologramTheme.TextPrimary, TextFormatFlags.Left | TextFormatFlags.VerticalCenter);
            TextRenderer.DrawText(g, "TOR-MESH 8 NODOS", new Font("Cascadia Mono", 7.8f, FontStyle.Bold),
                new Rectangle(65, 45, 185, 18), HologramTheme.HologramCyan, TextFormatFlags.Left | TextFormatFlags.VerticalCenter);
        };

        // Navigation Menu Stack
        var navContainer = new Panel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(0, 10, 0, 10),
            BackColor = Color.Transparent
        };

        var btnAjustes = CreateNavButton("settings", "⚙", "Ajustes");
        var btnRed = CreateNavButton("network", "◎", "Red de Nodos (IP)");
        var btnConsultas = CreateNavButton("history", "▤", "Consultas / Historial");
        _navSolicitudes = CreateNavButton("inbox", "✉", "Solicitudes");
        var btnDashboard = CreateNavButton("dashboard", "◆", "Dashboard / Cifrado");

        // Dock.Top agrega en orden inverso para quedar de arriba hacia abajo
        navContainer.Controls.Add(btnAjustes);
        navContainer.Controls.Add(btnRed);
        navContainer.Controls.Add(btnConsultas);
        navContainer.Controls.Add(_navSolicitudes);
        navContainer.Controls.Add(btnDashboard);

        // Bottom-Left Logged-in Profile Card
        var profileWrap = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 148,
            Padding = new Padding(12, 8, 12, 14),
            BackColor = Color.Transparent
        };
        var profileCard = new GlassPanel
        {
            Dock = DockStyle.Fill,
            CornerRadius = 15,
            BorderColor = Color.FromArgb(120, HologramTheme.AccentGlow),
            NeonBorderGlow = true,
            Padding = new Padding(12)
        };
        profileCard.Paint += (_, e) =>
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            var avRect = new Rectangle(14, 14, 44, 44);
            using var avBrush = new LinearGradientBrush(avRect, HologramTheme.AccentStart, HologramTheme.HologramCyan, 135f);
            g.FillEllipse(avBrush, avRect);
            using var ringPen = new Pen(HologramTheme.HologramCyan, 1.5f);
            g.DrawEllipse(ringPen, avRect);

            string initials = _currentUser.NombreUsuario.Length >= 2
                ? _currentUser.NombreUsuario[..2].ToUpperInvariant()
                : _currentUser.NombreUsuario.ToUpperInvariant();
            TextRenderer.DrawText(g, initials, new Font("Segoe UI", 12.5f, FontStyle.Bold), avRect, Color.White,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);

            // Online dot
            using var dotGlow = new SolidBrush(Color.FromArgb(90, HologramTheme.Success));
            g.FillEllipse(dotGlow, 46, 46, 14, 14);
            using var dot = new SolidBrush(HologramTheme.Success);
            g.FillEllipse(dot, 49, 49, 8, 8);
        };

        var lblProfName = new Label
        {
            Text = _currentUser.NombreUsuario,
            Font = new Font("Segoe UI Semibold", 10.5f, FontStyle.Bold),
            ForeColor = HologramTheme.TextPrimary,
            Location = new Point(66, 13),
            Size = new Size(160, 22),
            BackColor = Color.Transparent
        };
        var lblProfStatus = new Label
        {
            Text = $"● Online  •  {_currentUser.NodoAsignado}",
            Font = new Font("Cascadia Mono", 8.2f, FontStyle.Bold),
            ForeColor = HologramTheme.Success,
            Location = new Point(66, 36),
            Size = new Size(165, 18),
            BackColor = Color.Transparent
        };
        var lblProfRole = new Label
        {
            Text = _currentUser.Rol,
            Font = new Font("Segoe UI", 8.2f),
            ForeColor = HologramTheme.TextSecondary,
            Location = new Point(66, 54),
            Size = new Size(160, 18),
            BackColor = Color.Transparent
        };
        var btnLogout = new NeonButton
        {
            Text = "Cerrar Sesión",
            Variant = NeonButtonVariant.Secondary,
            Location = new Point(14, 80),
            Size = new Size(210, 32),
            CornerRadius = 9,
            Font = new Font("Segoe UI Semibold", 8.8f)
        };
        btnLogout.Click += (_, _) =>
        {
            SignOutRequested = true;
            Close();
        };

        profileCard.Controls.AddRange(new Control[] { lblProfName, lblProfStatus, lblProfRole, btnLogout });
        profileWrap.Controls.Add(profileCard);

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
            Height = 76,
            BackColor = Color.FromArgb(14, 11, 26),
            Padding = new Padding(22, 12, 22, 10)
        };
        topbar.Paint += (_, e) =>
        {
            using var pen = new Pen(HologramTheme.BorderSubtle, 1f);
            e.Graphics.DrawLine(pen, 0, topbar.Height - 1, topbar.Width, topbar.Height - 1);
        };

        var greetingPanel = new Panel { Dock = DockStyle.Left, Width = 310, BackColor = Color.Transparent };
        var lblWelcome = new Label
        {
            Text = $"Bienvenido, {_currentUser.NombreUsuario}",
            Font = new Font("Segoe UI", 15f, FontStyle.Bold),
            ForeColor = HologramTheme.TextPrimary,
            Location = new Point(0, 2),
            Size = new Size(305, 30)
        };
        var lblSubWelcome = new Label
        {
            Text = $"Nodo activo: {_currentUser.NodoAsignado}  •  IP local: {NodeRuntimeState.LocalIpAddress}",
            Font = new Font("Segoe UI", 8.8f),
            ForeColor = HologramTheme.TextSecondary,
            Location = new Point(0, 32),
            Size = new Size(305, 20)
        };
        greetingPanel.Controls.Add(lblWelcome);
        greetingPanel.Controls.Add(lblSubWelcome);

        // Selector del algoritmo activo (21 oficiales exclusivamente)
        var algPanel = new Panel { Dock = DockStyle.Right, Width = 310, BackColor = Color.Transparent };
        var lblAlgCap = new Label
        {
            Text = "ALGORITMO ACTIVO (21 OFICIALES)",
            Font = new Font("Cascadia Mono", 7.6f, FontStyle.Bold),
            ForeColor = HologramTheme.HologramViolet,
            Location = new Point(6, 2),
            Size = new Size(295, 16)
        };
        _cmbAlgorithm = new ComboBox
        {
            Location = new Point(6, 20),
            Size = new Size(298, 30),
            DropDownStyle = ComboBoxStyle.DropDownList,
            BackColor = HologramTheme.PanelGlassLight,
            ForeColor = HologramTheme.HologramCyan,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Cascadia Mono", 9.2f, FontStyle.Bold)
        };
        foreach (var alg in CryptoCatalog.OfficialAlgorithms)
            _cmbAlgorithm.Items.Add(alg);
        _cmbAlgorithm.SelectedIndex = 0;
        _cmbAlgorithm.SelectedIndexChanged += (_, _) => UpdateSelectedAlgorithmHud();
        algPanel.Controls.Add(lblAlgCap);
        algPanel.Controls.Add(_cmbAlgorithm);

        // Status pills centrales
        var pillsFlow = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            Padding = new Padding(8, 10, 8, 0),
            BackColor = Color.Transparent
        };
        _pillApi = new StatusPill
        {
            Text = NodeRuntimeState.ApiOnline ? $"API: Online :{NodeRuntimeState.ApiPort}" : "API: Offline",
            IsActive = NodeRuntimeState.ApiOnline,
            Width = 152
        };
        _pillSqlite = new StatusPill
        {
            Text = NodeRuntimeState.SqliteConnected ? "SQLite: Conectado" : "SQLite: Error",
            IsActive = NodeRuntimeState.SqliteConnected,
            Width = 158
        };
        _pillCert = new StatusPill
        {
            Text = NodeRuntimeState.CertificateActive ? "Certificado X.509: Activo" : "X.509: Inactivo",
            IsActive = NodeRuntimeState.CertificateActive,
            Width = 192
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
        var panel = new Panel { Dock = DockStyle.Fill, BackColor = Color.Transparent };
        _views["dashboard"] = panel;
        _viewHost.Controls.Add(panel);

        var split = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            BackColor = Color.Transparent
        };
        split.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 52f));
        split.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 48f));
        split.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));

        // === COLUMNA IZQUIERDA / CENTRO: HOLOGRAMA 3D BINARIO + CONTROLES PRINCIPALES ===
        var leftCol = new Panel { Dock = DockStyle.Fill, Padding = new Padding(0, 0, 10, 0), BackColor = Color.Transparent };

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
            StatusSubtitle = "Cubo Binario 3D en Reposo • Selecciona un archivo o texto para cifrar"
        };

        _lblAlgDesc = new Label
        {
            Dock = DockStyle.Bottom,
            Height = 36,
            Font = new Font("Segoe UI", 8.8f),
            ForeColor = HologramTheme.TextSecondary,
            TextAlign = ContentAlignment.MiddleCenter,
            BackColor = Color.Transparent
        };

        holoCard.Controls.Add(_hologram);
        holoCard.Controls.Add(_lblAlgDesc);

        // Barra inferior de acciones criptográficas y envío .ZIP
        var actionCard = new GlassPanel
        {
            Dock = DockStyle.Bottom,
            Height = 148,
            CornerRadius = 16,
            Padding = new Padding(14, 12, 14, 10)
        };

        var actionGrid = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 3,
            RowCount = 3,
            BackColor = Color.Transparent
        };
        actionGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
        actionGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
        actionGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.34f));
        actionGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
        actionGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 44));
        actionGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 44));

        // Fila 0: Passphrase opcional + Selector nodo destino
        _txtPassphrase = HologramTheme.CreateDarkTextBox();
        _txtPassphrase.Dock = DockStyle.Fill;
        _txtPassphrase.PlaceholderText = "Clave/frase opcional (o auto-generar segura)";
        _txtPassphrase.Margin = new Padding(3, 3, 6, 3);
        actionGrid.Controls.Add(_txtPassphrase, 0, 0);
        actionGrid.SetColumnSpan(_txtPassphrase, 2);

        _cmbTargetPeer = new ComboBox
        {
            Dock = DockStyle.Fill,
            DropDownStyle = ComboBoxStyle.DropDownList,
            BackColor = HologramTheme.PanelInput,
            ForeColor = HologramTheme.HologramCyan,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Cascadia Mono", 8.6f, FontStyle.Bold),
            Margin = new Padding(3, 3, 3, 3)
        };
        RefreshTargetPeerCombo();
        actionGrid.Controls.Add(_cmbTargetPeer, 2, 0);

        // Fila 1: Cargar Archivo, Cifrar, Descifrar Local
        var btnLoadFile = new NeonButton { Text = "📂 Cargar Archivo", Variant = NeonButtonVariant.Secondary, Dock = DockStyle.Fill, Margin = new Padding(3) };
        btnLoadFile.Click += (_, _) => HandleLoadFile();

        var btnEncrypt = new NeonButton { Text = "🔒 Cifrar Paquete", Variant = NeonButtonVariant.Primary, Dock = DockStyle.Fill, Margin = new Padding(3) };
        btnEncrypt.Click += (_, _) => HandleEncryptAction();

        var btnDecryptLocal = new NeonButton { Text = "🔓 Descifrar Local", Variant = NeonButtonVariant.Success, Dock = DockStyle.Fill, Margin = new Padding(3) };
        btnDecryptLocal.Click += (_, _) => HandleDecryptLocalAction();

        actionGrid.Controls.Add(btnLoadFile, 0, 1);
        actionGrid.Controls.Add(btnEncrypt, 1, 1);
        actionGrid.Controls.Add(btnDecryptLocal, 2, 1);

        // Fila 2: Descifrar Remoto, Enviar .ZIP a IP, Exportar .ZIP
        var btnDecryptRemote = new NeonButton { Text = "🌐 Descifrar Remoto", Variant = NeonButtonVariant.Cyan, Dock = DockStyle.Fill, Margin = new Padding(3) };
        btnDecryptRemote.Click += async (_, _) => await HandleDecryptRemoteActionAsync();

        var btnSendZip = new NeonButton { Text = "🚀 Enviar .ZIP a IP", Variant = NeonButtonVariant.Primary, Dock = DockStyle.Fill, Margin = new Padding(3) };
        btnSendZip.Click += async (_, _) => await HandleSendZipToPeerAsync();

        var btnExportZip = new NeonButton { Text = "📦 Exportar .ZIP", Variant = NeonButtonVariant.Secondary, Dock = DockStyle.Fill, Margin = new Padding(3) };
        btnExportZip.Click += (_, _) => HandleExportZipLocally();

        actionGrid.Controls.Add(btnDecryptRemote, 0, 2);
        actionGrid.Controls.Add(btnSendZip, 1, 2);
        actionGrid.Controls.Add(btnExportZip, 2, 2);

        actionCard.Controls.Add(actionGrid);

        var spacer = new Panel { Dock = DockStyle.Bottom, Height = 12, BackColor = Color.Transparent };
        leftCol.Controls.Add(holoCard);
        leftCol.Controls.Add(spacer);
        leftCol.Controls.Add(actionCard);

        // === COLUMNA DERECHA: VISOR (TEXTO/HEX/IMAGEN) + METADATOS NODO RAÍZ (TOR) ===
        var rightCol = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            Padding = new Padding(8, 0, 0, 0),
            BackColor = Color.Transparent
        };
        rightCol.RowStyles.Add(new RowStyle(SizeType.Percent, 54f));
        rightCol.RowStyles.Add(new RowStyle(SizeType.Percent, 46f));

        // Top Right Card: Visor Texto / Hex / Imagen
        var viewerCard = new GlassPanel
        {
            Dock = DockStyle.Fill,
            CornerRadius = 16,
            Padding = new Padding(14),
            Margin = new Padding(0, 0, 0, 12)
        };

        var viewerHeader = new Panel { Dock = DockStyle.Top, Height = 36, BackColor = Color.Transparent };
        _lblFileBadge = new Label
        {
            Text = "VISOR DE CARGA  •  mensaje_seguro.txt",
            Font = new Font("Segoe UI Semibold", 9.6f, FontStyle.Bold),
            ForeColor = HologramTheme.HologramCyan,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft
        };

        var modeButtons = new FlowLayoutPanel
        {
            Dock = DockStyle.Right,
            Width = 225,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            BackColor = Color.Transparent
        };
        _btnModeText = new NeonButton { Text = "Texto", Size = new Size(70, 28), CornerRadius = 8, Variant = NeonButtonVariant.Primary, Font = new Font("Segoe UI Semibold", 8.3f) };
        _btnModeHex = new NeonButton { Text = "Hex", Size = new Size(66, 28), CornerRadius = 8, Variant = NeonButtonVariant.Secondary, Font = new Font("Segoe UI Semibold", 8.3f) };
        _btnModeImg = new NeonButton { Text = "Imagen", Size = new Size(74, 28), CornerRadius = 8, Variant = NeonButtonVariant.Secondary, Font = new Font("Segoe UI Semibold", 8.3f) };

        _btnModeText.Click += (_, _) => SetViewerMode("TEXT");
        _btnModeHex.Click += (_, _) => SetViewerMode("HEX");
        _btnModeImg.Click += (_, _) => SetViewerMode("IMG");
        modeButtons.Controls.AddRange(new Control[] { _btnModeText, _btnModeHex, _btnModeImg });

        viewerHeader.Controls.Add(_lblFileBadge);
        viewerHeader.Controls.Add(modeButtons);

        var viewerBody = new Panel { Dock = DockStyle.Fill, Padding = new Padding(0, 8, 0, 0), BackColor = Color.Transparent };
        _txtDataViewer = HologramTheme.CreateDarkTextBox(multiline: true, readOnly: false, mono: true);
        _txtDataViewer.Dock = DockStyle.Fill;
        _txtDataViewer.TextChanged += (_, _) =>
        {
            if (_viewerMode == "TEXT" && !_isShowingEncrypted && _txtDataViewer.Focused)
            {
                _currentBytes = Encoding.UTF8.GetBytes(_txtDataViewer.Text);
                _currentFileName = "mensaje_manual.txt";
                _currentExtension = ".txt";
                _lblFileBadge.Text = $"VISOR DE CARGA  •  {_currentFileName} ({_currentBytes.Length} B)";
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
        viewerCard.Controls.Add(viewerHeader);

        // Bottom Right Card: Metadatos del Nodo Raíz (Trazabilidad Tor)
        var metaCard = new GlassPanel
        {
            Dock = DockStyle.Fill,
            CornerRadius = 16,
            Padding = new Padding(14)
        };

        var metaHeader = new Panel { Dock = DockStyle.Top, Height = 28, BackColor = Color.Transparent };
        var lblMetaTitle = new Label
        {
            Text = "TRAZABILIDAD TOR  •  METADATOS DEL NODO RAÍZ",
            Font = new Font("Segoe UI Semibold", 9.6f, FontStyle.Bold),
            ForeColor = HologramTheme.HologramViolet,
            Dock = DockStyle.Left,
            Width = 340
        };
        _lblMetaSignatureBadge = new Label
        {
            Text = "● X.509 Sin Operación",
            Font = new Font("Cascadia Mono", 8.4f, FontStyle.Bold),
            ForeColor = HologramTheme.TextSecondary,
            Dock = DockStyle.Right,
            Width = 180,
            TextAlign = ContentAlignment.MiddleRight
        };
        metaHeader.Controls.Add(lblMetaTitle);
        metaHeader.Controls.Add(_lblMetaSignatureBadge);

        var metaGrid = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 5,
            Padding = new Padding(0, 6, 0, 0),
            BackColor = Color.Transparent
        };
        metaGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 145));
        metaGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        metaGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        metaGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        metaGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        metaGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        metaGrid.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        _txtMetaPacketId = AddMetaRow(metaGrid, 0, "Packet ID (UUID):", "---");
        _txtMetaRootNode = AddMetaRow(metaGrid, 1, "Nodo Raíz:", _currentUser.NodoAsignado);
        _txtMetaHops = AddMetaRow(metaGrid, 2, "Ruta Saltos Tor:", $"[{_currentUser.NodoAsignado}]");
        _txtMetaRemoteLink = AddMetaRow(metaGrid, 3, "Link Remoto:", "http://...");

        var lblPub = new Label
        {
            Text = "Parámetros JSON:",
            Font = new Font("Segoe UI Semibold", 8.6f),
            ForeColor = HologramTheme.TextSecondary,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.TopLeft,
            Padding = new Padding(0, 6, 0, 0)
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
            TextAlign = ContentAlignment.MiddleLeft
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
        _lblFileBadge.Text = $"VISOR  •  {_currentFileName} ({_currentBytes.Length:N0} bytes)" +
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
            Filter = "Todos los archivos (*.*)|*.*|Imágenes (*.png;*.bmp;*.jpg)|*.png;*.bmp;*.jpg|Texto / JSON (*.txt;*.json)|*.txt;*.json"
        };
        if (ofd.ShowDialog(this) != DialogResult.OK) return;

        _currentBytes = File.ReadAllBytes(ofd.FileName);
        _currentFileName = Path.GetFileName(ofd.FileName);
        _currentExtension = Path.GetExtension(ofd.FileName);
        _isShowingEncrypted = false;
        _hologram.SetIdle($"Archivo cargado: {_currentFileName} ({_currentBytes.Length:N0} bytes)");

        string ext = _currentExtension.ToLowerInvariant();
        if (ext is ".png" or ".bmp" or ".jpg" or ".jpeg")
            SetViewerMode("IMG");
        else if (_currentBytes.Length > 65536 || _currentBytes.Take(256).Any(b => b == 0))
            SetViewerMode("HEX");
        else
            SetViewerMode("TEXT");
    }

    private void HandleEncryptAction()
    {
        if (_cmbAlgorithm.SelectedItem is not CryptoAlgorithmInfo algInfo) return;

        try
        {
            if (_viewerMode == "TEXT" && !_isShowingEncrypted)
                _currentBytes = Encoding.UTF8.GetBytes(_txtDataViewer.Text);

            var strategy = CryptoCatalog.GetStrategy(algInfo.Code);
            var result = strategy.Encrypt(_currentBytes, _txtPassphrase.Text);

            string packetId = Guid.NewGuid().ToString();
            string signature = NodeCertificateService.SignPayload(result.OutputBytes);
            string remoteLink = NodeRuntimeState.BuildRemoteDecryptUrl(packetId);
            var hops = new List<string> { _currentUser.NodoAsignado };

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
                NodoRaiz = _currentUser.NodoAsignado,
                FirmaRaizBase64 = signature,
                RutaSaltosJson = JsonSerializer.Serialize(hops),
                Origen = "Local",
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

    private void HandleDecryptLocalAction()
    {
        if (_activeRecord == null)
        {
            MessageBox.Show(this, "Primero cifra un paquete o carga un registro desde Consultas / Solicitudes.",
                "ModuloCrypto", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        ExecuteDecryption(_activeRecord.AlgoritmoCodigo, _currentBytes, _activeRecord.LlaveSecretaBase64, _activeRecord.ParametrosPublicosJson);
    }

    private async Task HandleDecryptRemoteActionAsync()
    {
        string url = _txtMetaRemoteLink.Text.Trim();
        if (string.IsNullOrWhiteSpace(url) || !url.StartsWith("http", StringComparison.OrdinalIgnoreCase))
        {
            MessageBox.Show(this, "No hay un Link de Descifrado Remoto válido en los metadatos activos.",
                "ModuloCrypto", MessageBoxButtons.OK, MessageBoxIcon.Warning);
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
            _hologram.TriggerDecryptAnimation(algCode);

            if (_viewerMode == "IMG" && algCode == "LSBSTEGO")
                SetViewerMode("TEXT");
            else
                RenderCurrentBytesInViewer();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Error al descifrar ({algCode}):\n{ex.Message}",
                "ModuloCrypto — Error de Descifrado", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private async Task HandleSendZipToPeerAsync()
    {
        if (_activeRecord == null)
        {
            MessageBox.Show(this, "Primero cifra un mensaje o archivo para generar un paquete .zip.",
                "ModuloCrypto", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        string targetPeerId = _cmbTargetPeer.SelectedItem?.ToString()?.Split(' ')[0] ?? "NODO-04";
        var peer = NodeRuntimeState.NetworkPeers.FirstOrDefault(p => p.NodeId == targetPeerId)
                   ?? NodeRuntimeState.NetworkPeers.First();

        try
        {
            byte[] cipherBytes = Convert.FromBase64String(_activeRecord.BytesCifrados);
            var hops = PacketZipService.TryDeserializeHops(_activeRecord.RutaSaltosJson);
            if (!hops.Contains(peer.NodeId)) hops.Add(peer.NodeId);

            string zipPath = PacketZipService.CreatePacketZip(_activeRecord, cipherBytes, hops);
            var sendResult = await NodeNetworkClient.SendZipPacketAsync(peer.BaseUrl, zipPath);

            MessageBox.Show(this, sendResult.Message,
                sendResult.Success ? "Envío Tor .ZIP Exitoso" : "Error de Envío .ZIP",
                MessageBoxButtons.OK,
                sendResult.Success ? MessageBoxIcon.Information : MessageBoxIcon.Error);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"No se pudo empaquetar/enviar el .ZIP:\n{ex.Message}",
                "ModuloCrypto", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void HandleExportZipLocally()
    {
        if (_activeRecord == null)
        {
            MessageBox.Show(this, "Primero cifra un paquete para exportarlo como .zip.",
                "ModuloCrypto", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        using var sfd = new SaveFileDialog
        {
            Filter = "Paquete Tor ModuloCrypto (*.zip)|*.zip",
            FileName = $"{_activeRecord.NodoRaiz}_{_activeRecord.AlgoritmoCodigo}_{_activeRecord.PacketId[..8]}.zip"
        };
        if (sfd.ShowDialog(this) != DialogResult.OK) return;

        byte[] cipherBytes = Convert.FromBase64String(_activeRecord.BytesCifrados);
        PacketZipService.CreatePacketZip(_activeRecord, cipherBytes, destinationPath: sfd.FileName);
        MessageBox.Show(this, $"Paquete .zip exportado con manifest.json y certificado X.509:\n{sfd.FileName}",
            "Exportación Exitosa", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void UpdateMetadataPanel(RegistroCifrado r, bool signatureValid)
    {
        _txtMetaPacketId.Text = r.PacketId;
        _txtMetaRootNode.Text = $"{r.NodoRaiz}  ({r.Origen})";
        _txtMetaHops.Text = string.Join("  →  ", PacketZipService.TryDeserializeHops(r.RutaSaltosJson));
        _txtMetaRemoteLink.Text = r.LinkDescifradoRemoto;

        try
        {
            using var doc = JsonDocument.Parse(r.ParametrosPublicosJson);
            _txtMetaPublicJson.Text = JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true });
        }
        catch
        {
            _txtMetaPublicJson.Text = r.ParametrosPublicosJson;
        }

        _lblMetaSignatureBadge.Text = signatureValid ? "● Firma X.509 VÁLIDA" : "● Firma X.509 INVÁLIDA";
        _lblMetaSignatureBadge.ForeColor = signatureValid ? HologramTheme.Success : HologramTheme.Danger;
    }

    private void HandleIncomingPacketEvent(SolicitudEntrante solicitud)
    {
        if (IsDisposed) return;
        BeginInvoke(() =>
        {
            RefreshPendingSolicitudesBadge();
            RefreshSolicitudesGrid();
            _hologram.StatusSubtitle = $"Nuevo paquete .ZIP recibido de {solicitud.NodoOrigen} ({solicitud.AlgoritmoCodigo})";
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
        _cmbTargetPeer.SelectedIndex = prev >= 0 && prev < _cmbTargetPeer.Items.Count ? prev : 3;
    }

    private void RefreshAllDataViews()
    {
        RefreshSolicitudesGrid();
        RefreshConsultasGrid();
        RefreshNetworkGrid();
        RefreshSettingsStats();
    }
}
