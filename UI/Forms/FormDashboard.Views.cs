using ModuloCrypto.Core.Data;
using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using ModuloCrypto.Network;
using ModuloCrypto.Security;
using ModuloCrypto.UI.Controls;
using ModuloCrypto.UI.Theme;
using System.Drawing;
using System.Text.Json;
using System.Windows.Forms;

namespace ModuloCrypto.UI.Forms;

public partial class FormDashboard
{
    // Solicitudes (Bandeja)
    private DataGridView _gridSolicitudes = null!;

    // Consultas (Historial)
    private DataGridView _gridConsultas = null!;
    private TextBox _txtSearchHistory = null!;
    private ComboBox _cmbFilterOrigin = null!;

    // Red de Nodos (IP)
    private DataGridView _gridPeers = null!;
    private TextBox _txtEditPeerIp = null!;
    private TextBox _txtEditPeerPort = null!;

    // Ajustes
    private Label _lblSettingsDbStats = null!;
    private TextBox _txtSettingsCertInfo = null!;

    private void BuildSolicitudesView()
    {
        var panel = new Panel { Dock = DockStyle.Fill, BackColor = HologramTheme.BackgroundBase, Visible = false };
        _views["inbox"] = panel;
        _viewHost.Controls.Add(panel);

        var card = new GlassPanel { Dock = DockStyle.Fill, CornerRadius = 18, Padding = new Padding(18) };

        var header = new Panel { Dock = DockStyle.Top, Height = 58, BackColor = HologramTheme.PanelGlass };
        var lblTitle = new Label
        {
            Text = "Bandeja de Solicitudes Entrantes (.ZIP) — NODO-01",
            Font = new Font("Segoe UI", 14.5f, FontStyle.Bold),
            ForeColor = HologramTheme.TextPrimary,
            Location = new Point(0, 0),
            Size = new Size(520, 28),
            BackColor = HologramTheme.PanelGlass
        };
        var lblSub = new Label
        {
            Text = "Recibe paquetes, descifra como Nodo Final o re-cifra con otro algoritmo para reenviar como Nodo Intermedio",
            Font = HologramTheme.FontBody(9f),
            ForeColor = HologramTheme.TextSecondary,
            Location = new Point(0, 30),
            Size = new Size(640, 20),
            BackColor = HologramTheme.PanelGlass
        };

        var btnFlow = new FlowLayoutPanel
        {
            Dock = DockStyle.Right,
            Width = 570,
            FlowDirection = FlowDirection.RightToLeft,
            WrapContents = false,
            Padding = new Padding(0, 8, 0, 0),
            BackColor = HologramTheme.PanelGlass
        };

        var btnRefresh = new NeonButton { Text = "↻ Actualizar", Variant = NeonButtonVariant.Secondary, Size = new Size(112, 36) };
        btnRefresh.Click += (_, _) => { RefreshSolicitudesGrid(); RefreshPendingSolicitudesBadge(); };

        var btnImportZip = new NeonButton { Text = "📥 Importar .ZIP", Variant = NeonButtonVariant.Cyan, Size = new Size(134, 36) };
        btnImportZip.Click += (_, _) => HandleImportZipToInbox();

        var btnReject = new NeonButton { Text = "✕ Rechazar", Variant = NeonButtonVariant.Danger, Size = new Size(116, 36) };
        btnReject.Click += (_, _) => HandleUpdateSolicitudEstado("Rechazada");

        var btnAccept = new NeonButton { Text = "✓ Aceptar y Descifrar", Variant = NeonButtonVariant.Success, Size = new Size(180, 36) };
        btnAccept.Click += async (_, _) => await HandleAcceptAndDecryptSolicitudAsync();

        btnFlow.Controls.AddRange(new Control[] { btnRefresh, btnImportZip, btnReject, btnAccept });
        header.Controls.Add(lblTitle);
        header.Controls.Add(lblSub);
        header.Controls.Add(btnFlow);

        _gridSolicitudes = new DataGridView { Dock = DockStyle.Fill };
        HologramTheme.StyleDataGrid(_gridSolicitudes);
        _gridSolicitudes.CellFormatting += (_, e) =>
        {
            if (_gridSolicitudes.Columns[e.ColumnIndex].Name == "FirmaX509" && e.Value is string s)
                e.CellStyle!.ForeColor = s.Contains("Válida") ? HologramTheme.Success : HologramTheme.Danger;
            else if (_gridSolicitudes.Columns[e.ColumnIndex].Name == "Estado" && e.Value is string st)
                e.CellStyle!.ForeColor = st == "Aceptada" ? HologramTheme.Success :
                                         st == "Rechazada" ? HologramTheme.Danger : HologramTheme.Warning;
        };

        var gridWrap = new Panel { Dock = DockStyle.Fill, Padding = new Padding(0, 12, 0, 0), BackColor = HologramTheme.PanelGlass };
        gridWrap.Controls.Add(_gridSolicitudes);

        card.Controls.Add(gridWrap);
        card.Controls.Add(header);
        panel.Controls.Add(card);
    }

    private void RefreshSolicitudesGrid()
    {
        if (_gridSolicitudes == null) return;
        using var db = new AppDbContext();
        var rows = db.SolicitudesEntrantes
            .OrderByDescending(s => s.FechaRecepcion)
            .Select(s => new
            {
                s.Id,
                PacketId = s.PacketId.Length > 12 ? s.PacketId.Substring(0, 12) + "..." : s.PacketId,
                NodoRaiz = s.NodoOrigen,
                s.IpOrigen,
                s.NombreZip,
                Algoritmo = s.AlgoritmoCodigo,
                FirmaX509 = s.FirmaX509Valida ? "✓ Válida" : "✕ Inválida",
                s.Estado,
                Recibido = s.FechaRecepcion.ToString("yyyy-MM-dd HH:mm:ss")
            })
            .ToList();
        _gridSolicitudes.DataSource = rows;
    }

    private void HandleImportZipToInbox()
    {
        using var ofd = new OpenFileDialog { Filter = "Paquete ModuloCrypto (*.zip)|*.zip" };
        if (ofd.ShowDialog(this) != DialogResult.OK) return;

        try
        {
            var parsed = PacketZipService.ReadPacketZip(ofd.FileName);
            string dir = Path.Combine(AppContext.BaseDirectory, "IncomingPackets");
            Directory.CreateDirectory(dir);
            string dest = Path.Combine(dir, $"{Guid.NewGuid().ToString()[..6]}_{Path.GetFileName(ofd.FileName)}");
            File.Copy(ofd.FileName, dest, true);

            using var db = new AppDbContext();
            db.SolicitudesEntrantes.Add(new SolicitudEntrante
            {
                PacketId = parsed.Manifest.PacketId,
                NodoOrigen = parsed.Manifest.NodoRaiz,
                IpOrigen = "Importación Local",
                NombreZip = Path.GetFileName(ofd.FileName),
                AlgoritmoCodigo = parsed.Manifest.AlgoritmoCodigo,
                FirmaX509Valida = parsed.SignatureValid && parsed.IntegrityValid,
                RutaZipTemporal = dest,
                Estado = "Pendiente",
                FechaRecepcion = DateTime.Now
            });
            db.SaveChanges();

            RefreshSolicitudesGrid();
            RefreshPendingSolicitudesBadge();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Error al leer paquete .zip:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void HandleUpdateSolicitudEstado(string nuevoEstado)
    {
        if (_gridSolicitudes.SelectedRows.Count == 0) return;
        int id = Convert.ToInt32(_gridSolicitudes.SelectedRows[0].Cells["Id"].Value);
        using var db = new AppDbContext();
        var sol = db.SolicitudesEntrantes.Find(id);
        if (sol == null) return;
        sol.Estado = nuevoEstado;
        db.SaveChanges();
        RefreshSolicitudesGrid();
        RefreshPendingSolicitudesBadge();
    }

    private async Task HandleAcceptAndDecryptSolicitudAsync()
    {
        if (_gridSolicitudes.SelectedRows.Count == 0) return;
        int id = Convert.ToInt32(_gridSolicitudes.SelectedRows[0].Cells["Id"].Value);

        using var db = new AppDbContext();
        var sol = db.SolicitudesEntrantes.Find(id);
        if (sol == null || !File.Exists(sol.RutaZipTemporal))
        {
            MessageBox.Show(this, "No se encontró el archivo .zip temporal de esta solicitud.", "ModuloCrypto — NODO-01", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        try
        {
            var parsed = PacketZipService.ReadPacketZip(sol.RutaZipTemporal);
            string? secretKey = null;
            string pubJson = parsed.Manifest.ParametrosPublicosJson;

            if (!string.IsNullOrWhiteSpace(parsed.Manifest.LinkDescifradoRemoto))
            {
                var remote = await NodeNetworkClient.RequestRemoteKeyAsync(parsed.Manifest.LinkDescifradoRemoto);
                if (remote.Success)
                {
                    secretKey = remote.LlaveSecretaBase64;
                    if (!string.IsNullOrWhiteSpace(remote.ParametrosPublicosJson))
                        pubJson = remote.ParametrosPublicosJson;
                }
            }

            if (string.IsNullOrWhiteSpace(secretKey))
            {
                var localMatch = db.RegistrosCifrados.FirstOrDefault(r => r.PacketId == parsed.Manifest.PacketId);
                if (localMatch != null)
                    secretKey = localMatch.LlaveSecretaBase64;
            }

            if (string.IsNullOrWhiteSpace(secretKey))
            {
                MessageBox.Show(this, $"No se pudo obtener la llave remota desde:\n{parsed.Manifest.LinkDescifradoRemoto}",
                    "Llave No Disponible", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            var hops = parsed.Manifest.RutaSaltos ?? new List<string>();
            if (hops.Count == 0) hops.Add(parsed.Manifest.NodoRaiz);
            if (hops[^1] != "NODO-01") hops.Add("NODO-01");

            // Guardar contexto de relay por si NODO-01 desea actuar como Nodo Intermedio (re-cifrar con otro algoritmo y reenviar)
            _relayRootOrigin = parsed.Manifest.NodoRaiz;
            _relayRootSignatureBase64 = parsed.Manifest.FirmaRaizBase64;
            _relayRootCertBase64 = parsed.Manifest.CertificadoRaizBase64;
            _relayOriginalHashHex = parsed.Manifest.OriginalHashSha256;
            _relayHopHistory = new List<string>(hops);

            var registroRecibido = new RegistroCifrado
            {
                UsuarioId = _currentUser.Id,
                PacketId = parsed.Manifest.PacketId,
                NombreArchivo = parsed.Manifest.NombreArchivo,
                Extension = parsed.Manifest.Extension,
                BytesCifrados = Convert.ToBase64String(parsed.PayloadBytes),
                AlgoritmoCodigo = parsed.Manifest.AlgoritmoCodigo,
                ParametrosPublicosJson = pubJson,
                LlaveSecretaBase64 = secretKey,
                LinkDescifradoRemoto = parsed.Manifest.LinkDescifradoRemoto,
                NodoRaiz = parsed.Manifest.NodoRaiz,
                FirmaRaizBase64 = parsed.Manifest.FirmaRaizBase64,
                RutaSaltosJson = JsonSerializer.Serialize(hops),
                Origen = "Recibido",
                FechaOperacion = DateTime.Now
            };

            db.RegistrosCifrados.Add(registroRecibido);
            sol.Estado = "Aceptada";
            db.SaveChanges();

            _activeRecord = registroRecibido;
            _currentFileName = registroRecibido.NombreArchivo;
            _currentExtension = registroRecibido.Extension;
            _currentBytes = parsed.PayloadBytes;
            SelectAlgorithmInCombo(registroRecibido.AlgoritmoCodigo);
            UpdateMetadataPanel(registroRecibido, parsed.SignatureValid && parsed.IntegrityValid);

            RefreshSolicitudesGrid();
            RefreshPendingSolicitudesBadge();
            RefreshConsultasGrid();

            SwitchView("dashboard");
            ExecuteDecryption(registroRecibido.AlgoritmoCodigo, parsed.PayloadBytes, secretKey, pubJson);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Error al procesar solicitud:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void BuildConsultasView()
    {
        var panel = new Panel { Dock = DockStyle.Fill, BackColor = HologramTheme.BackgroundBase, Visible = false };
        _views["history"] = panel;
        _viewHost.Controls.Add(panel);

        var card = new GlassPanel { Dock = DockStyle.Fill, CornerRadius = 18, Padding = new Padding(18) };

        var header = new Panel { Dock = DockStyle.Top, Height = 60, BackColor = HologramTheme.PanelGlass };
        var lblTitle = new Label
        {
            Text = "Consultas e Historial de Registros Cifrados (NODO-01)",
            Font = new Font("Segoe UI", 14.5f, FontStyle.Bold),
            ForeColor = HologramTheme.TextPrimary,
            Location = new Point(0, 0),
            Size = new Size(490, 28),
            BackColor = HologramTheme.PanelGlass
        };

        _txtSearchHistory = HologramTheme.CreateDarkTextBox();
        _txtSearchHistory.PlaceholderText = "Buscar por archivo, algoritmo, NodoRaiz o PacketId...";
        _txtSearchHistory.Location = new Point(0, 30);
        _txtSearchHistory.Size = new Size(290, 26);
        _txtSearchHistory.TextChanged += (_, _) => RefreshConsultasGrid();

        _cmbFilterOrigin = new ComboBox
        {
            Location = new Point(300, 30),
            Size = new Size(140, 26),
            Font = new Font("Segoe UI Semibold", 9f)
        };
        HologramTheme.StyleComboBox(_cmbFilterOrigin);
        _cmbFilterOrigin.Items.AddRange(new object[] { "Todos", "Local", "Relay", "Recibido" });
        _cmbFilterOrigin.SelectedIndex = 0;
        _cmbFilterOrigin.SelectedIndexChanged += (_, _) => RefreshConsultasGrid();

        var btnFlow = new FlowLayoutPanel
        {
            Dock = DockStyle.Right,
            Width = 510,
            FlowDirection = FlowDirection.RightToLeft,
            WrapContents = false,
            Padding = new Padding(0, 10, 0, 0),
            BackColor = HologramTheme.PanelGlass
        };

        var btnCopyLink = new NeonButton { Text = "🔗 Copiar Link", Variant = NeonButtonVariant.Secondary, Size = new Size(124, 36) };
        btnCopyLink.Click += (_, _) =>
        {
            var r = GetSelectedRegistro();
            if (r == null) return;
            Clipboard.SetText(r.LinkDescifradoRemoto);
            MessageBox.Show(this, $"Link remoto copiado:\n{r.LinkDescifradoRemoto}", "Portapapeles", MessageBoxButtons.OK, MessageBoxIcon.Information);
        };

        var btnLoad = new NeonButton { Text = "⚡ Cargar en Dashboard", Variant = NeonButtonVariant.Primary, Size = new Size(184, 36) };
        btnLoad.Click += (_, _) => LoadSelectedHistoryRecord();

        var btnDelete = new NeonButton { Text = "🗑 Eliminar", Variant = NeonButtonVariant.Danger, Size = new Size(110, 36) };
        btnDelete.Click += (_, _) =>
        {
            var r = GetSelectedRegistro();
            if (r == null) return;
            using var db = new AppDbContext();
            var entity = db.RegistrosCifrados.Find(r.Id);
            if (entity != null) { db.RegistrosCifrados.Remove(entity); db.SaveChanges(); }
            RefreshConsultasGrid();
        };

        btnFlow.Controls.AddRange(new Control[] { btnDelete, btnCopyLink, btnLoad });
        header.Controls.Add(lblTitle);
        header.Controls.Add(_txtSearchHistory);
        header.Controls.Add(_cmbFilterOrigin);
        header.Controls.Add(btnFlow);

        _gridConsultas = new DataGridView { Dock = DockStyle.Fill };
        HologramTheme.StyleDataGrid(_gridConsultas);
        _gridConsultas.CellDoubleClick += (_, _) => LoadSelectedHistoryRecord();

        var gridWrap = new Panel { Dock = DockStyle.Fill, Padding = new Padding(0, 12, 0, 0), BackColor = HologramTheme.PanelGlass };
        gridWrap.Controls.Add(_gridConsultas);

        card.Controls.Add(gridWrap);
        card.Controls.Add(header);
        panel.Controls.Add(card);
    }

    private void RefreshConsultasGrid()
    {
        if (_gridConsultas == null) return;
        string q = _txtSearchHistory?.Text.Trim().ToLowerInvariant() ?? "";
        string origin = _cmbFilterOrigin?.SelectedItem?.ToString() ?? "Todos";

        using var db = new AppDbContext();
        var query = db.RegistrosCifrados.AsQueryable();

        if (origin != "Todos")
            query = query.Where(r => r.Origen == origin);

        var list = query
            .OrderByDescending(r => r.FechaOperacion)
            .ToList()
            .Where(r => string.IsNullOrEmpty(q) ||
                        r.NombreArchivo.ToLowerInvariant().Contains(q) ||
                        r.AlgoritmoCodigo.ToLowerInvariant().Contains(q) ||
                        r.PacketId.ToLowerInvariant().Contains(q) ||
                        r.NodoRaiz.ToLowerInvariant().Contains(q))
            .Select(r => new
            {
                r.Id,
                PacketId = r.PacketId.Length > 12 ? r.PacketId[..12] + "..." : r.PacketId,
                Archivo = r.NombreArchivo,
                Algoritmo = r.AlgoritmoCodigo,
                r.NodoRaiz,
                RutaSaltos = string.Join(" → ", PacketZipService.TryDeserializeHops(r.RutaSaltosJson)),
                r.Origen,
                Fecha = r.FechaOperacion.ToString("yyyy-MM-dd HH:mm:ss")
            })
            .ToList();

        _gridConsultas.DataSource = list;
    }

    private RegistroCifrado? GetSelectedRegistro()
    {
        if (_gridConsultas.SelectedRows.Count == 0) return null;
        int id = Convert.ToInt32(_gridConsultas.SelectedRows[0].Cells["Id"].Value);
        using var db = new AppDbContext();
        return db.RegistrosCifrados.Find(id);
    }

    private void LoadSelectedHistoryRecord()
    {
        var r = GetSelectedRegistro();
        if (r == null) return;

        _activeRecord = r;
        _currentBytes = Convert.FromBase64String(r.BytesCifrados);
        _currentFileName = r.NombreArchivo;
        _currentExtension = r.Extension;
        _isShowingEncrypted = true;

        _relayRootOrigin = r.NodoRaiz;
        _relayRootSignatureBase64 = r.FirmaRaizBase64;
        _relayHopHistory = PacketZipService.TryDeserializeHops(r.RutaSaltosJson);

        SelectAlgorithmInCombo(r.AlgoritmoCodigo);
        UpdateMetadataPanel(r, !string.IsNullOrWhiteSpace(r.FirmaRaizBase64));
        _hologram.TriggerEncryptAnimation(r.AlgoritmoCodigo);

        if (r.AlgoritmoCodigo == "LSBSTEGO") SetViewerMode("IMG");
        else RenderCurrentBytesInViewer();

        SwitchView("dashboard");
    }

    private void SelectAlgorithmInCombo(string code)
    {
        for (int i = 0; i < _cmbAlgorithm.Items.Count; i++)
        {
            if (_cmbAlgorithm.Items[i] is CryptoAlgorithmInfo info &&
                string.Equals(info.Code, code, StringComparison.OrdinalIgnoreCase))
            {
                _cmbAlgorithm.SelectedIndex = i;
                break;
            }
        }
    }

    private void BuildNetworkView()
    {
        var panel = new Panel { Dock = DockStyle.Fill, BackColor = HologramTheme.BackgroundBase, Visible = false };
        _views["network"] = panel;
        _viewHost.Controls.Add(panel);

        var card = new GlassPanel { Dock = DockStyle.Fill, CornerRadius = 18, Padding = new Padding(18) };

        var header = new Panel { Dock = DockStyle.Top, Height = 58, BackColor = HologramTheme.PanelGlass };
        var lblTitle = new Label
        {
            Text = "Topología de Red Distribuida (8 Nodos Bidireccionales)",
            Font = new Font("Segoe UI", 14.5f, FontStyle.Bold),
            ForeColor = HologramTheme.TextPrimary,
            Location = new Point(0, 0),
            Size = new Size(520, 28),
            BackColor = HologramTheme.PanelGlass
        };
        var lblSub = new Label
        {
            Text = "Nuestro equipo es NODO-01. Todos los nodos pueden iniciar circuitos, actuar como salto intermedio o nodo final.",
            Font = HologramTheme.FontBody(9f),
            ForeColor = HologramTheme.TextSecondary,
            Location = new Point(0, 30),
            Size = new Size(640, 20),
            BackColor = HologramTheme.PanelGlass
        };

        var btnPingAll = new NeonButton
        {
            Text = "📡 Escanear / Ping 8 Nodos",
            Variant = NeonButtonVariant.Cyan,
            Dock = DockStyle.Right,
            Width = 225,
            Height = 38
        };
        btnPingAll.Click += async (_, _) =>
        {
            btnPingAll.Enabled = false;
            btnPingAll.Text = "Escaneando red...";
            foreach (var peer in NodeRuntimeState.NetworkPeers)
            {
                var (online, latency, info) = await NodeNetworkClient.PingNodeAsync(peer);
                peer.IsOnline = online;
                peer.LastLatency = latency;
                if (info != null && !string.IsNullOrWhiteSpace(info.X509Thumbprint))
                    peer.CertThumbprint = info.X509Thumbprint[..Math.Min(16, info.X509Thumbprint.Length)] + "...";
            }
            RefreshNetworkGrid();
            btnPingAll.Text = "📡 Escanear / Ping 8 Nodos";
            btnPingAll.Enabled = true;
        };

        header.Controls.Add(lblTitle);
        header.Controls.Add(lblSub);
        header.Controls.Add(btnPingAll);

        var editBar = new Panel { Dock = DockStyle.Bottom, Height = 54, Padding = new Padding(0, 12, 0, 0), BackColor = HologramTheme.PanelGlass };
        var lblIp = new Label
        {
            Text = "IP del Nodo Seleccionado:",
            ForeColor = HologramTheme.TextSecondary,
            Location = new Point(0, 18),
            Size = new Size(165, 22),
            Font = HologramTheme.FontBody(9.2f),
            BackColor = HologramTheme.PanelGlass
        };
        _txtEditPeerIp = HologramTheme.CreateDarkTextBox();
        _txtEditPeerIp.Location = new Point(170, 15);
        _txtEditPeerIp.Size = new Size(180, 28);

        var lblPort = new Label
        {
            Text = "Puerto:",
            ForeColor = HologramTheme.TextSecondary,
            Location = new Point(365, 18),
            Size = new Size(56, 22),
            Font = HologramTheme.FontBody(9.2f),
            BackColor = HologramTheme.PanelGlass
        };
        _txtEditPeerPort = HologramTheme.CreateDarkTextBox();
        _txtEditPeerPort.Location = new Point(422, 15);
        _txtEditPeerPort.Size = new Size(80, 28);
        _txtEditPeerPort.Text = "5000";

        var btnSavePeer = new NeonButton
        {
            Text = "Guardar IP de Nodo",
            Variant = NeonButtonVariant.Primary,
            Location = new Point(518, 12),
            Size = new Size(175, 34)
        };
        btnSavePeer.Click += (_, _) =>
        {
            if (_gridPeers.SelectedRows.Count == 0) return;
            string nodeId = _gridPeers.SelectedRows[0].Cells["NodeId"].Value?.ToString() ?? "";
            var peer = NodeRuntimeState.NetworkPeers.FirstOrDefault(p => p.NodeId == nodeId);
            if (peer == null) return;
            peer.IpAddress = _txtEditPeerIp.Text.Trim();
            if (int.TryParse(_txtEditPeerPort.Text.Trim(), out int port) && port > 0 && port < 65536)
                peer.Port = port;
            RefreshNetworkGrid();
            RefreshTargetPeerCombo();
        };

        editBar.Controls.AddRange(new Control[] { lblIp, _txtEditPeerIp, lblPort, _txtEditPeerPort, btnSavePeer });

        _gridPeers = new DataGridView { Dock = DockStyle.Fill };
        HologramTheme.StyleDataGrid(_gridPeers);
        _gridPeers.SelectionChanged += (_, _) =>
        {
            if (_gridPeers.SelectedRows.Count == 0) return;
            string nodeId = _gridPeers.SelectedRows[0].Cells["NodeId"].Value?.ToString() ?? "";
            var peer = NodeRuntimeState.NetworkPeers.FirstOrDefault(p => p.NodeId == nodeId);
            if (peer != null)
            {
                _txtEditPeerIp.Text = peer.IpAddress;
                _txtEditPeerPort.Text = peer.Port.ToString();
            }
        };
        _gridPeers.CellFormatting += (_, e) =>
        {
            if (_gridPeers.Columns[e.ColumnIndex].Name == "Estado" && e.Value is string s)
                e.CellStyle!.ForeColor = s.Contains("Online") ? HologramTheme.Success : HologramTheme.Danger;
        };

        var gridWrap = new Panel { Dock = DockStyle.Fill, Padding = new Padding(0, 12, 0, 0), BackColor = HologramTheme.PanelGlass };
        gridWrap.Controls.Add(_gridPeers);

        card.Controls.Add(gridWrap);
        card.Controls.Add(editBar);
        card.Controls.Add(header);
        panel.Controls.Add(card);
    }

    private void RefreshNetworkGrid()
    {
        if (_gridPeers == null) return;
        _gridPeers.DataSource = NodeRuntimeState.NetworkPeers.Select(p => new
        {
            p.NodeId,
            Rol = p.RoleLabel,
            Endpoint = p.BaseUrl,
            Estado = p.IsOnline ? "● Online" : "● Offline",
            Latencia = p.LastLatency,
            CertificadoX509 = p.CertThumbprint
        }).ToList();
    }

    private void BuildSettingsView()
    {
        var panel = new Panel { Dock = DockStyle.Fill, BackColor = HologramTheme.BackgroundBase, Visible = false };
        _views["settings"] = panel;
        _viewHost.Controls.Add(panel);

        var grid = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            BackColor = HologramTheme.BackgroundBase
        };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50f));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50f));

        // Izquierda: Certificado X.509 & API (NODO-01)
        var leftCard = new GlassPanel { Dock = DockStyle.Fill, CornerRadius = 18, Padding = new Padding(20), Margin = new Padding(0, 0, 10, 0) };
        var lblCertTitle = new Label
        {
            Text = "Identidad NODO-01 & Certificado X.509",
            Font = new Font("Segoe UI", 14f, FontStyle.Bold),
            ForeColor = HologramTheme.HologramCyan,
            Dock = DockStyle.Top,
            Height = 36,
            BackColor = HologramTheme.PanelGlass
        };
        _txtSettingsCertInfo = HologramTheme.CreateDarkTextBox(multiline: true, readOnly: true, mono: true);
        _txtSettingsCertInfo.Dock = DockStyle.Fill;

        var btnRegen = new NeonButton
        {
            Text = "🔄 Regenerar Certificado X.509 (CN=NODO-01)",
            Variant = NeonButtonVariant.Primary,
            Dock = DockStyle.Bottom,
            Height = 42
        };
        btnRegen.Click += (_, _) =>
        {
            NodeCertificateService.Initialize(forceRegenerate: true);
            RefreshSettingsStats();
            MessageBox.Show(this, "Nuevo certificado X.509 RSA-2048 generado para CN=NODO-01 y guardado en node_identity.pfx.",
                "Certificado X.509 — NODO-01", MessageBoxButtons.OK, MessageBoxIcon.Information);
        };

        var certSpacer = new Panel { Dock = DockStyle.Bottom, Height = 12, BackColor = HologramTheme.PanelGlass };
        leftCard.Controls.Add(_txtSettingsCertInfo);
        leftCard.Controls.Add(certSpacer);
        leftCard.Controls.Add(btnRegen);
        leftCard.Controls.Add(lblCertTitle);

        // Derecha: Base de Datos SQLite & Pruebas de Animación Holograma
        var rightCard = new GlassPanel { Dock = DockStyle.Fill, CornerRadius = 18, Padding = new Padding(20), Margin = new Padding(10, 0, 0, 0) };
        var lblDbTitle = new Label
        {
            Text = "Base de Datos SQLite & Diagnóstico Visual",
            Font = new Font("Segoe UI", 14f, FontStyle.Bold),
            ForeColor = HologramTheme.HologramViolet,
            Dock = DockStyle.Top,
            Height = 36,
            BackColor = HologramTheme.PanelGlass
        };

        _lblSettingsDbStats = new Label
        {
            Dock = DockStyle.Top,
            Height = 165,
            Font = HologramTheme.FontMono(9.5f),
            ForeColor = HologramTheme.TextPrimary,
            Padding = new Padding(0, 10, 0, 10),
            BackColor = HologramTheme.PanelGlass
        };

        var lblHoloTest = new Label
        {
            Text = "PRUEBA RÁPIDA DE ESTADOS DEL HOLOGRAMA 3D:",
            Dock = DockStyle.Top,
            Height = 30,
            Font = new Font("Segoe UI Semibold", 9.5f, FontStyle.Bold),
            ForeColor = HologramTheme.HologramCyan,
            BackColor = HologramTheme.PanelGlass
        };

        var testFlow = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = 160,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            BackColor = HologramTheme.PanelGlass
        };

        var btnTestIdle = new NeonButton { Text = "1. Estado Reposo (Cubo Binario 3D)", Variant = NeonButtonVariant.Secondary, Size = new Size(340, 40) };
        btnTestIdle.Click += (_, _) => { _hologram.SetIdle("Prueba Manual • Cubo Binario 3D"); SwitchView("dashboard"); };

        var btnTestLock = new NeonButton { Text = "2. Estado Cifrar (Candado Cerrado)", Variant = NeonButtonVariant.Primary, Size = new Size(340, 40) };
        btnTestLock.Click += (_, _) => { _hologram.TriggerEncryptAnimation("AESGCM"); SwitchView("dashboard"); };

        var btnTestUnlock = new NeonButton { Text = "3. Estado Descifrar (Candado Abierto)", Variant = NeonButtonVariant.Success, Size = new Size(340, 40) };
        btnTestUnlock.Click += (_, _) => { _hologram.TriggerDecryptAnimation("AESGCM"); SwitchView("dashboard"); };

        testFlow.Controls.AddRange(new Control[] { btnTestIdle, btnTestLock, btnTestUnlock });

        rightCard.Controls.Add(testFlow);
        rightCard.Controls.Add(lblHoloTest);
        rightCard.Controls.Add(_lblSettingsDbStats);
        rightCard.Controls.Add(lblDbTitle);

        grid.Controls.Add(leftCard, 0, 0);
        grid.Controls.Add(rightCard, 1, 0);
        panel.Controls.Add(grid);
    }

    private void RefreshSettingsStats()
    {
        if (_txtSettingsCertInfo == null || _lblSettingsDbStats == null) return;

        var cert = NodeCertificateService.CurrentCertificate;
        _txtSettingsCertInfo.Text =
            $"Nodo Activo        : NODO-01\r\n" +
            $"Operador Logueado  : {_userFullName} ({_currentUser.NombreUsuario})\r\n" +
            $"API Embebida       : http://0.0.0.0:{NodeRuntimeState.ApiPort}\r\n" +
            $"IP Local Detectada : {NodeRuntimeState.LocalIpAddress}\r\n" +
            $"Estado API         : {(NodeRuntimeState.ApiOnline ? "Online" : "Offline")}\r\n" +
            $"---------------------------------------------------\r\n" +
            $"X.509 Subject      : {cert.Subject}\r\n" +
            $"X.509 Thumbprint   : {cert.Thumbprint}\r\n" +
            $"Válido Desde       : {cert.NotBefore:yyyy-MM-dd HH:mm}\r\n" +
            $"Válido Hasta       : {cert.NotAfter:yyyy-MM-dd HH:mm}\r\n" +
            $"Algoritmos Activos : {CryptoCatalog.OfficialAlgorithms.Count} oficiales";

        using var db = new AppDbContext();
        int uCount = db.Usuarios.Count();
        int rCount = db.RegistrosCifrados.Count();
        int sCount = db.SolicitudesEntrantes.Count();
        int sPend = db.SolicitudesEntrantes.Count(s => s.Estado == "Pendiente");

        _lblSettingsDbStats.Text =
            $"Archivo SQLite     : {AppDbContext.DatabasePath}\r\n" +
            $"Tabla Usuarios     : {uCount} integrante(s)\r\n" +
            $"Tabla Consultas    : {rCount} registro(s) cifrado(s)\r\n" +
            $"Tabla Solicitudes  : {sCount} total ({sPend} pendiente(s))\r\n" +
            $"Rol de Red         : NODO-01 (Inicio / Intermedio / Final)";
    }
}
