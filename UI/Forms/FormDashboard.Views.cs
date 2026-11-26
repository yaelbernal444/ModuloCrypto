using ModuloCrypto.Core.Contracts;
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

    // Red de Nodos (IP / TOFU / UDP 5099)
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
            Text = $"Bandeja de Solicitudes Entrantes (.ZIP v2.0) — {NodeRuntimeState.CurrentNodeId}",
            Font = new Font("Segoe UI", 14f, FontStyle.Bold),
            ForeColor = HologramTheme.TextPrimary,
            Location = new Point(0, 0),
            Size = new Size(490, 28),
            BackColor = HologramTheme.PanelGlass
        };
        var lblSub = new Label
        {
            Text = "Validación estricta de 3 archivos planos, Anti-ZIP-Bomb, RSA-PSS-SHA256 (11 campos), TOFU y Anti-Replay",
            Font = HologramTheme.FontBody(8.8f),
            ForeColor = HologramTheme.TextSecondary,
            Location = new Point(0, 30),
            Size = new Size(560, 20),
            BackColor = HologramTheme.PanelGlass
        };

        var btnFlow = new FlowLayoutPanel
        {
            Dock = DockStyle.Right,
            Width = 670,
            FlowDirection = FlowDirection.RightToLeft,
            WrapContents = false,
            Padding = new Padding(0, 8, 0, 0),
            BackColor = HologramTheme.PanelGlass
        };

        var btnRefresh = new NeonButton { Text = "↻ Actualizar", Variant = NeonButtonVariant.Secondary, Size = new Size(106, 36) };
        btnRefresh.Click += (_, _) => { RefreshSolicitudesGrid(); RefreshPendingSolicitudesBadge(); };

        var btnImportZip = new NeonButton { Text = "📥 Importar .ZIP", Variant = NeonButtonVariant.Cyan, Size = new Size(128, 36) };
        btnImportZip.Click += (_, _) => HandleImportZipToInbox();

        var btnForwardV2 = new NeonButton { Text = "↪ Reenviar v2.0", Variant = NeonButtonVariant.Primary, Size = new Size(134, 36) };
        btnForwardV2.Click += async (_, _) => await HandleForwardSelectedSolicitudV2Async();

        var btnReject = new NeonButton { Text = "✕ Rechazar", Variant = NeonButtonVariant.Danger, Size = new Size(106, 36) };
        btnReject.Click += (_, _) => HandleUpdateSolicitudEstado("Rechazada");

        var btnAccept = new NeonButton { Text = "✓ Aceptar y Descifrar", Variant = NeonButtonVariant.Success, Size = new Size(168, 36) };
        btnAccept.Click += (_, _) => HandleAcceptAndDecryptSolicitud();

        btnFlow.Controls.AddRange(new Control[] { btnRefresh, btnImportZip, btnForwardV2, btnReject, btnAccept });
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
                SourceNode = s.NodoOrigen,
                s.IpOrigen,
                s.NombreZip,
                Algoritmo = s.AlgoritmoCodigo,
                FirmaX509 = s.FirmaX509Valida ? "✓ RSA-PSS Válida" : "✕ Inválida",
                s.Estado,
                Recibido = s.FechaRecepcion.ToString("yyyy-MM-dd HH:mm:ss")
            })
            .ToList();
        _gridSolicitudes.DataSource = rows;
    }

    private void HandleImportZipToInbox()
    {
        using var ofd = new OpenFileDialog { Filter = "Paquete Estándar v2.0 (*.zip)|*.zip" };
        if (ofd.ShowDialog(this) != DialogResult.OK) return;

        try
        {
            var parsed = PacketZipService.ReadPacketZip(ofd.FileName, enforceStrictSignature: true);
            string dir = Path.Combine(AppContext.BaseDirectory, "IncomingPackets");
            Directory.CreateDirectory(dir);
            string dest = Path.Combine(dir, $"{Guid.NewGuid().ToString("N")[..6]}_{Path.GetFileName(ofd.FileName)}");
            File.Copy(ofd.FileName, dest, true);

            using var db = new AppDbContext();
            db.SolicitudesEntrantes.Add(new SolicitudEntrante
            {
                PacketId = parsed.Manifest.PacketId,
                NodoOrigen = parsed.Manifest.SourceNode,
                IpOrigen = "Importación Local v2.0",
                NombreZip = Path.GetFileName(ofd.FileName),
                AlgoritmoCodigo = parsed.Manifest.AlgorithmCode,
                FirmaX509Valida = parsed.SignatureValid && parsed.IntegrityValid,
                RutaZipTemporal = dest,
                Estado = "Pendiente",
                FechaRecepcion = DateTime.Now
            });
            db.SaveChanges();

            RefreshSolicitudesGrid();
            RefreshPendingSolicitudesBadge();
        }
        catch (PacketValidationException pve)
        {
            MessageBox.Show(this,
                $"Paquete .zip rechazado por validación de seguridad v2.0:\n\n" +
                $"• Código de Error : {pve.ErrorCode} (HTTP {pve.HttpStatusCode})\n" +
                $"• Detalle         : {pve.Message}",
                "Rechazo de Seguridad v2.0",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Error al leer paquete .zip:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private async Task HandleForwardSelectedSolicitudV2Async()
    {
        if (_gridSolicitudes.SelectedRows.Count == 0) return;
        int id = Convert.ToInt32(_gridSolicitudes.SelectedRows[0].Cells["Id"].Value);

        using var db = new AppDbContext();
        var sol = db.SolicitudesEntrantes.Find(id);
        if (sol == null || !File.Exists(sol.RutaZipTemporal))
        {
            MessageBox.Show(this, "No se encontró el archivo .zip temporal de esta solicitud.", "ModuloCrypto", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        try
        {
            string targetPeerId = _cmbTargetPeer.SelectedItem?.ToString()?.Split(' ')[0] ?? "EQ02";
            var peer = NodeRuntimeState.NetworkPeers.FirstOrDefault(p => p.NodeId == targetPeerId)
                       ?? NodeRuntimeState.NetworkPeers.First();

            string repackagedZip = PacketZipService.RepackageForForwarding(sol.RutaZipTemporal);
            var parsed = PacketZipService.ReadPacketZip(repackagedZip, enforceStrictSignature: true);
            var sendRes = await NodeNetworkClient.SendZipPacketAsync(peer, repackagedZip, parsed.Manifest.PacketId, parsed.Manifest.PacketType);

            MessageBox.Show(this,
                $"{sendRes.Message}\n\n" +
                $"• Nuevo PacketId : {parsed.Manifest.PacketId}\n" +
                $"• ProducerNode   : {parsed.Manifest.ProducerNode} (conservado)\n" +
                $"• SourceNode     : {parsed.Manifest.SourceNode} (re-firmado)",
                sendRes.Success ? "Reenvío Estándar v2.0 (Sección 9.6) Exitoso" : "Error en Reenvío v2.0",
                MessageBoxButtons.OK,
                sendRes.Success ? MessageBoxIcon.Information : MessageBoxIcon.Error);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Error al reempaquetar para reenvío v2.0:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
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

    private void HandleAcceptAndDecryptSolicitud()
    {
        if (_gridSolicitudes.SelectedRows.Count == 0) return;
        int id = Convert.ToInt32(_gridSolicitudes.SelectedRows[0].Cells["Id"].Value);

        using var db = new AppDbContext();
        var sol = db.SolicitudesEntrantes.Find(id);
        if (sol == null || !File.Exists(sol.RutaZipTemporal))
        {
            MessageBox.Show(this, "No se encontró el archivo .zip temporal de esta solicitud.", "ModuloCrypto", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        try
        {
            var parsed = PacketZipService.ReadPacketZip(sol.RutaZipTemporal, enforceStrictSignature: true);
            string? secretKey = null;
            string pubJson = JsonSerializer.Serialize(parsed.Manifest.PublicParameters);

            // 1. Buscar llave por keyRef.keyId o PacketId en la base de datos local (cuando EQ01 es el ownerNode)
            string lookupKeyId = parsed.Manifest.KeyRef?.KeyId ?? parsed.Manifest.PacketId;
            var localMatch = db.RegistrosCifrados.FirstOrDefault(r =>
                r.PacketId == lookupKeyId || r.PacketId == parsed.Manifest.PacketId);

            if (localMatch != null && !string.IsNullOrWhiteSpace(localMatch.LlaveSecretaBase64))
            {
                secretKey = localMatch.LlaveSecretaBase64;
                if (string.IsNullOrWhiteSpace(pubJson) || pubJson == "{}")
                    pubJson = localMatch.ParametrosPublicosJson;
            }

            // 2. Si la llave no reside en EQ01, solicitar clave/passphrase al operador en modal seguro
            if (string.IsNullOrWhiteSpace(secretKey))
            {
                string? manualKey = PromptExternalPassphraseModal(
                    parsed.Manifest.AlgorithmCode,
                    parsed.Manifest.ProducerNode,
                    parsed.Manifest.SourceNode,
                    parsed.SignatureValid);
                if (manualKey == null)
                    return;
                secretKey = manualKey;
            }

            var hops = new List<string> { parsed.Manifest.ProducerNode };
            if (!hops.Contains(parsed.Manifest.SourceNode))
                hops.Add(parsed.Manifest.SourceNode);
            if (!hops.Contains(NodeRuntimeState.CurrentNodeId))
                hops.Add(NodeRuntimeState.CurrentNodeId);

            pubJson = EnrichPublicParametersWithOriginalFileMeta(pubJson, parsed.Manifest.OriginalFileName, parsed.Manifest.OriginalExtension);

            _relayProducerNode = parsed.Manifest.ProducerNode;
            _relayHopHistory = new List<string>(hops);
            _relaySourceZipPath = sol.RutaZipTemporal;
            _isFromNetworkUntrusted = true;

            string keyRefDisplay = parsed.Manifest.KeyRef != null
                ? $"keyRef://{parsed.Manifest.KeyRef.OwnerNode}/{parsed.Manifest.KeyRef.KeyId}"
                : $"keyRef://{parsed.Manifest.ProducerNode}/{parsed.Manifest.PacketId}";

            var registroRecibido = new RegistroCifrado
            {
                UsuarioId = _currentUser.Id,
                PacketId = parsed.Manifest.PacketId,
                NombreArchivo = parsed.Manifest.OriginalFileName,
                Extension = parsed.Manifest.OriginalExtension,
                BytesCifrados = Convert.ToBase64String(parsed.PayloadBytes),
                AlgoritmoCodigo = parsed.Manifest.AlgorithmCode,
                ParametrosPublicosJson = pubJson,
                LlaveSecretaBase64 = secretKey,
                LinkDescifradoRemoto = keyRefDisplay,
                NodoRaiz = parsed.Manifest.ProducerNode,
                FirmaRaizBase64 = parsed.Manifest.ManifestSignatureBase64,
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
            bool hasSig = !string.IsNullOrWhiteSpace(parsed.Manifest.ManifestSignatureBase64);
            UpdateMetadataPanel(registroRecibido, parsed.SignatureValid && parsed.IntegrityValid, hasSig);

            RefreshSolicitudesGrid();
            RefreshPendingSolicitudesBadge();
            RefreshConsultasGrid();

            SwitchView("dashboard");
            ExecuteDecryption(registroRecibido.AlgoritmoCodigo, parsed.PayloadBytes, secretKey, pubJson);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Error al procesar solicitud v2.0:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private string? PromptExternalPassphraseModal(string algCode, string producerNode, string sourceNode, bool sigValid)
    {
        string defaultKey = algCode.ToUpperInvariant() switch
        {
            "AESGCM" => "clave-aes-256-segura",
            "CHACHA20" => "chacha20-llave-32bytes",
            "DES" => "claveDES",
            "TRIPLEDES" => "clave-3des-96-ede",
            "VIGENERE" => "CRIPTOGRAFIA",
            "CAESAR" => "3",
            _ => "clave-prueba"
        };

        using var dlg = new Form
        {
            Text = "Clave de Descifrado de Paquete v2.0",
            FormBorderStyle = FormBorderStyle.None,
            StartPosition = FormStartPosition.CenterParent,
            Size = new Size(470, 300),
            BackColor = HologramTheme.BackgroundBase,
            ForeColor = HologramTheme.TextPrimary,
            KeyPreview = true
        };

        var card = new GlassPanel
        {
            Dock = DockStyle.Fill,
            CornerRadius = 16,
            NeonBorderGlow = true,
            BorderColor = HologramTheme.AccentStart,
            Padding = new Padding(24)
        };

        var lblTitle = new Label
        {
            Text = $"Descifrar Paquete v2.0 ({algCode})",
            Font = new Font("Segoe UI", 14f, FontStyle.Bold),
            ForeColor = HologramTheme.HologramCyan,
            Location = new Point(24, 20),
            Size = new Size(420, 28),
            BackColor = HologramTheme.PanelGlass
        };

        string sigNote = sigValid ? "✓ Firma RSA-PSS-SHA256 verificada" : "⚠ Firma no verificada";
        var lblSub = new Label
        {
            Text = $"Producer: {producerNode} • Source: {sourceNode} • {sigNote}\nIngresa la clave o llave Base64 para descifrar:",
            Font = new Font("Segoe UI", 9.2f),
            ForeColor = HologramTheme.TextSecondary,
            Location = new Point(24, 54),
            Size = new Size(420, 42),
            BackColor = HologramTheme.PanelGlass
        };

        var txtKey = HologramTheme.CreateDarkTextBox();
        txtKey.Location = new Point(24, 112);
        txtKey.Size = new Size(420, 34);
        txtKey.Font = new Font("Cascadia Mono", 10.5f);
        txtKey.Text = defaultKey;

        var lblHint = new Label
        {
            Text = "Las llaves nunca viajan dentro de manifest.json (Estándar v2.0).",
            Font = new Font("Segoe UI", 8.4f),
            ForeColor = HologramTheme.HologramViolet,
            Location = new Point(24, 152),
            Size = new Size(420, 22),
            BackColor = HologramTheme.PanelGlass
        };

        string? resultKey = null;

        var btnOk = new NeonButton
        {
            Text = "🔓 Aceptar y Descifrar",
            Variant = NeonButtonVariant.Success,
            Location = new Point(24, 204),
            Size = new Size(204, 42)
        };
        btnOk.Click += (_, _) =>
        {
            resultKey = txtKey.Text;
            dlg.DialogResult = DialogResult.OK;
            dlg.Close();
        };

        var btnCancel = new NeonButton
        {
            Text = "Cancelar",
            Variant = NeonButtonVariant.Secondary,
            Location = new Point(240, 204),
            Size = new Size(204, 42)
        };
        btnCancel.Click += (_, _) =>
        {
            dlg.DialogResult = DialogResult.Cancel;
            dlg.Close();
        };

        card.Controls.AddRange(new Control[] { lblTitle, lblSub, txtKey, lblHint, btnOk, btnCancel });
        dlg.Controls.Add(card);

        dlg.KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.Enter)
            {
                e.SuppressKeyPress = true;
                resultKey = txtKey.Text;
                dlg.DialogResult = DialogResult.OK;
                dlg.Close();
            }
            else if (e.KeyCode == Keys.Escape)
            {
                dlg.DialogResult = DialogResult.Cancel;
                dlg.Close();
            }
        };

        return dlg.ShowDialog(this) == DialogResult.OK ? resultKey : null;
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
            Text = $"Consultas e Historial de Registros Cifrados ({NodeRuntimeState.CurrentNodeId})",
            Font = new Font("Segoe UI", 14.5f, FontStyle.Bold),
            ForeColor = HologramTheme.TextPrimary,
            Location = new Point(0, 0),
            Size = new Size(490, 28),
            BackColor = HologramTheme.PanelGlass
        };

        _txtSearchHistory = HologramTheme.CreateDarkTextBox();
        _txtSearchHistory.PlaceholderText = "Buscar por archivo, algoritmo, ProducerNode o PacketId...";
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

        var btnCopyKeyRef = new NeonButton { Text = "🔑 Copiar keyRef", Variant = NeonButtonVariant.Secondary, Size = new Size(124, 36) };
        btnCopyKeyRef.Click += (_, _) =>
        {
            var r = GetSelectedRegistro();
            if (r == null) return;
            string kr = string.IsNullOrWhiteSpace(r.LinkDescifradoRemoto) ? $"keyRef://{r.NodoRaiz}/{r.PacketId}" : r.LinkDescifradoRemoto;
            Clipboard.SetText(kr);
            MessageBox.Show(this, $"Referencia keyRef copiada:\n{kr}", "Portapapeles", MessageBoxButtons.OK, MessageBoxIcon.Information);
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

        btnFlow.Controls.AddRange(new Control[] { btnDelete, btnCopyKeyRef, btnLoad });
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
                ProducerNode = r.NodoRaiz,
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
        _relaySourceZipPath = null;
        _isFromNetworkUntrusted = string.Equals(r.Origen, "Recibido", StringComparison.OrdinalIgnoreCase);
        _currentBytes = Convert.FromBase64String(r.BytesCifrados);
        _currentFileName = r.NombreArchivo;
        _currentExtension = r.Extension;
        _isShowingEncrypted = true;
        _binarySummaryReport = null;
        _lastSavedDecryptedPath = null;

        _relayProducerNode = r.NodoRaiz;
        _relayHopHistory = PacketZipService.TryDeserializeHops(r.RutaSaltosJson);

        SelectAlgorithmInCombo(r.AlgoritmoCodigo);
        UpdateMetadataPanel(r, !string.IsNullOrWhiteSpace(r.FirmaRaizBase64), !string.IsNullOrWhiteSpace(r.FirmaRaizBase64));
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

        var header = new Panel { Dock = DockStyle.Top, Height = 64, BackColor = HologramTheme.PanelGlass };
        var lblTitle = new Label
        {
            Text = "Directorio de Nodos v2.0 (UDP 5099 • Escaneo 5001–5020 • TOFU)",
            Font = new Font("Segoe UI", 13.5f, FontStyle.Bold),
            ForeColor = HologramTheme.TextPrimary,
            Location = new Point(0, 0),
            Size = new Size(440, 28),
            BackColor = HologramTheme.PanelGlass
        };
        var lblSub = new Label
        {
            Text = $"Beacons CC-BEACON cada 30s (timeout 90s) y fijado de huella SHA-256 TOFU",
            Font = HologramTheme.FontBody(8.6f),
            ForeColor = HologramTheme.TextSecondary,
            Location = new Point(0, 30),
            Size = new Size(440, 20),
            BackColor = HologramTheme.PanelGlass
        };

        var netBtnFlow = new FlowLayoutPanel
        {
            Dock = DockStyle.Right,
            Width = 760,
            FlowDirection = FlowDirection.RightToLeft,
            WrapContents = false,
            Padding = new Padding(0, 10, 0, 0),
            BackColor = HologramTheme.PanelGlass
        };

        var btnPingAll = new NeonButton
        {
            Text = "📡 Ping / Verificar TOFU",
            Variant = NeonButtonVariant.Cyan,
            Size = new Size(176, 38),
            Font = new Font("Segoe UI Semibold", 8.5f, FontStyle.Bold)
        };
        btnPingAll.Click += async (_, _) =>
        {
            btnPingAll.Enabled = false;
            btnPingAll.Text = "Verificando...";
            foreach (var peer in NodeRuntimeState.NetworkPeers)
            {
                await NodeNetworkClient.PingNodeAsync(peer, customTimeoutMs: 500);
            }
            RefreshNetworkGrid();
            btnPingAll.Text = "📡 Ping / Verificar TOFU";
            btnPingAll.Enabled = true;
        };

        var btnConfirmTofu = new NeonButton
        {
            Text = "🛡 Confirmar Huella TOFU",
            Variant = NeonButtonVariant.Success,
            Size = new Size(184, 38),
            Font = new Font("Segoe UI Semibold", 8.5f, FontStyle.Bold)
        };
        btnConfirmTofu.Click += (_, _) => HandleConfirmSelectedPeerTofu();

        var btnScanLocalhost = new NeonButton
        {
            Text = "💻 Localhost (5001-5020)",
            Variant = NeonButtonVariant.Primary,
            Size = new Size(184, 38),
            Font = new Font("Segoe UI Semibold", 8.5f, FontStyle.Bold)
        };
        btnScanLocalhost.Click += async (_, _) =>
        {
            btnScanLocalhost.Enabled = false;
            btnScanLocalhost.Text = "Escaneando 127.0.0.1...";
            var found = await NodeNetworkClient.ScanLocalhostPortsAsync(5001, 5020);
            int integrated = IntegrateDiscoveredPeers(found);
            RefreshNetworkGrid();
            RefreshTargetPeerCombo();
            btnScanLocalhost.Text = "💻 Localhost (5001-5020)";
            btnScanLocalhost.Enabled = true;

            MessageBox.Show(this,
                $"Escaneo de Localhost (puertos 5001–5020, timeout 500 ms) completado.\n" +
                $"• Nodos v2.0 detectados: {found.Count}\n" +
                $"• Nodos actualizados en directorio: {integrated}",
                "Descubrimiento Localhost v2.0", MessageBoxButtons.OK, MessageBoxIcon.Information);
        };

        var btnScanLan = new NeonButton
        {
            Text = "🔍 Subred LAN (5001-5020)",
            Variant = NeonButtonVariant.Secondary,
            Size = new Size(190, 38),
            Font = new Font("Segoe UI Semibold", 8.5f, FontStyle.Bold)
        };
        btnScanLan.Click += async (_, _) =>
        {
            btnScanLan.Enabled = false;
            btnScanLan.Text = "Escaneando /24...";
            var (found, _) = await NodeNetworkClient.ScanLanSubnetAsync(NodeRuntimeState.LocalIpAddress, 5001, 5020, isAutomaticTrigger: false);
            int integrated = IntegrateDiscoveredPeers(found);
            RefreshNetworkGrid();
            RefreshTargetPeerCombo();
            btnScanLan.Text = "🔍 Subred LAN (5001-5020)";
            btnScanLan.Enabled = true;

            MessageBox.Show(this,
                $"Escaneo HTTP de respaldo en subred /24 (puertos 5001–5020, máx 64 conexiones) completado.\n" +
                $"• Nodos v2.0 detectados: {found.Count}\n" +
                $"• Nodos integrados en directorio: {integrated}",
                "Escaneo HTTP Subred v2.0", MessageBoxButtons.OK, MessageBoxIcon.Information);
        };

        netBtnFlow.Controls.AddRange(new Control[] { btnPingAll, btnConfirmTofu, btnScanLocalhost, btnScanLan });

        header.Controls.Add(lblTitle);
        header.Controls.Add(lblSub);
        header.Controls.Add(netBtnFlow);

        var editBar = new Panel { Dock = DockStyle.Bottom, Height = 54, Padding = new Padding(0, 12, 0, 0), BackColor = HologramTheme.PanelGlass };
        var lblIp = new Label
        {
            Text = "Alta Manual IP Nodo:",
            ForeColor = HologramTheme.TextSecondary,
            Location = new Point(0, 18),
            Size = new Size(150, 22),
            Font = HologramTheme.FontBody(9.2f),
            BackColor = HologramTheme.PanelGlass
        };
        _txtEditPeerIp = HologramTheme.CreateDarkTextBox();
        _txtEditPeerIp.Location = new Point(155, 15);
        _txtEditPeerIp.Size = new Size(180, 28);

        var lblPort = new Label
        {
            Text = "Puerto:",
            ForeColor = HologramTheme.TextSecondary,
            Location = new Point(350, 18),
            Size = new Size(56, 22),
            Font = HologramTheme.FontBody(9.2f),
            BackColor = HologramTheme.PanelGlass
        };
        _txtEditPeerPort = HologramTheme.CreateDarkTextBox();
        _txtEditPeerPort.Location = new Point(408, 15);
        _txtEditPeerPort.Size = new Size(80, 28);
        _txtEditPeerPort.Text = "5001";

        var btnSavePeer = new NeonButton
        {
            Text = "Guardar y Verificar Nodo",
            Variant = NeonButtonVariant.Primary,
            Location = new Point(502, 12),
            Size = new Size(195, 34)
        };
        btnSavePeer.Click += async (_, _) =>
        {
            if (_gridPeers.SelectedRows.Count == 0) return;
            string nodeId = _gridPeers.SelectedRows[0].Cells["NodeId"].Value?.ToString() ?? "";
            var peer = NodeRuntimeState.NetworkPeers.FirstOrDefault(p => p.NodeId == nodeId);
            if (peer == null) return;
            peer.IpAddress = _txtEditPeerIp.Text.Trim();
            if (int.TryParse(_txtEditPeerPort.Text.Trim(), out int port) && port > 0 && port < 65536)
                peer.Port = port;
            peer.Source = "manual";
            await NodeNetworkClient.PingNodeAsync(peer, customTimeoutMs: 800);
            AppDbContext.UpsertTrustedPeer(peer);
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
            string colName = _gridPeers.Columns[e.ColumnIndex].Name;
            if (colName == "Estado" && e.Value is string s)
            {
                e.CellStyle!.ForeColor = s.Contains("BLOQUEADO") ? HologramTheme.Danger :
                                         s.Contains("Online") ? HologramTheme.Success : HologramTheme.TextSecondary;
            }
            else if (colName == "ConfianzaTOFU" && e.Value is string tofu)
            {
                e.CellStyle!.ForeColor = tofu.Contains("CAMBIO") ? HologramTheme.Danger :
                                         tofu.Contains("Fijada") ? HologramTheme.Success : HologramTheme.Warning;
            }
        };

        var gridWrap = new Panel { Dock = DockStyle.Fill, Padding = new Padding(0, 12, 0, 0), BackColor = HologramTheme.PanelGlass };
        gridWrap.Controls.Add(_gridPeers);

        card.Controls.Add(gridWrap);
        card.Controls.Add(editBar);
        card.Controls.Add(header);
        panel.Controls.Add(card);
    }

    private void HandleConfirmSelectedPeerTofu()
    {
        if (_gridPeers.SelectedRows.Count == 0) return;
        string nodeId = _gridPeers.SelectedRows[0].Cells["NodeId"].Value?.ToString() ?? "";
        var peer = NodeRuntimeState.NetworkPeers.FirstOrDefault(p => p.NodeId == nodeId);
        if (peer == null) return;

        if (string.IsNullOrWhiteSpace(peer.CertThumbprint))
        {
            MessageBox.Show(this,
                $"El nodo {peer.NodeId} aún no ha anunciado un certificado X.509.\nEjecuta primero [📡 Ping / Verificar TOFU] o espera su beacon UDP 5099.",
                "TOFU — Sin Huella", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        string msg = peer.HasThumbprintMismatch
            ? $"🚨 ADVERTENCIA DE SEGURIDAD TOFU 🚨\n\n" +
              $"El nodo {peer.NodeId} ({peer.BaseUrl}) cambió su huella X.509:\n" +
              $"• Huella Anterior Fijada : {peer.PinnedThumbprintSha256}\n" +
              $"• Nueva Huella Presentada: {peer.CertThumbprint}\n\n" +
              $"¿Confirmas que el equipo {peer.NodeId} regeneró legítimamente su certificado y deseas desbloquearlo fijando la nueva huella?"
            : $"Confirmación TOFU (Trust On First Use) para {peer.NodeId} ({peer.BaseUrl}):\n\n" +
              $"• Huella SHA-256 (64 HEX):\n{peer.CertThumbprint}\n\n" +
              $"¿Deseas fijar esta huella como confiable en SQLite (TrustedPeers)?";

        if (MessageBox.Show(this, msg, $"Confirmar TOFU — {peer.NodeId}",
            MessageBoxButtons.YesNo,
            peer.HasThumbprintMismatch ? MessageBoxIcon.Warning : MessageBoxIcon.Question) == DialogResult.Yes)
        {
            NodeNetworkClient.ConfirmPeerTofu(peer);
            RefreshNetworkGrid();
        }
    }

    private static int IntegrateDiscoveredPeers(List<PeerNode> discovered)
    {
        int count = 0;
        foreach (var d in discovered)
        {
            var existing = NodeRuntimeState.NetworkPeers.FirstOrDefault(p =>
                p.NodeId.Equals(d.NodeId, StringComparison.OrdinalIgnoreCase));

            if (existing != null)
            {
                existing.IpAddress = d.IpAddress;
                existing.Port = d.Port;
                existing.Source = d.Source;
                existing.LastLatency = d.LastLatency;
                existing.CertThumbprint = d.CertThumbprint;
                existing.CertificatePem = d.CertificatePem;
                existing.AlgorithmsJson = d.AlgorithmsJson;
                existing.HasThumbprintMismatch = d.HasThumbprintMismatch;
                existing.Status = d.Status;
                existing.LastSeenUtc = DateTime.UtcNow;
                AppDbContext.UpsertTrustedPeer(existing);
                count++;
            }
            else
            {
                NodeRuntimeState.NetworkPeers.Add(d);
                AppDbContext.UpsertTrustedPeer(d);
                count++;
            }
        }
        return count;
    }

    private void RefreshNetworkGrid()
    {
        if (_gridPeers == null) return;
        _gridPeers.DataSource = NodeRuntimeState.NetworkPeers.Select(p => new
        {
            p.NodeId,
            Rol = p.RoleLabel,
            Origen = p.Source,
            Endpoint = p.BaseUrl,
            Estado = p.HasThumbprintMismatch ? "⛔ BLOQUEADO TOFU" : (p.IsOnline ? "● Online" : "● Offline"),
            ConfianzaTOFU = p.HasThumbprintMismatch ? "🚨 CAMBIO DE HUELLA" :
                            (p.IsConfirmed ? "✓ Fijada (TOFU)" : "⚠ Pendiente Confirmar"),
            Latencia = p.LastLatency,
            HuellaSHA256 = string.IsNullOrWhiteSpace(p.CertThumbprint)
                ? "Sin verificar"
                : (p.CertThumbprint.Length > 16 ? p.CertThumbprint[..16] + "..." : p.CertThumbprint)
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

        var leftCard = new GlassPanel { Dock = DockStyle.Fill, CornerRadius = 18, Padding = new Padding(20), Margin = new Padding(0, 0, 10, 0) };
        var lblCertTitle = new Label
        {
            Text = $"Identidad {NodeRuntimeState.CurrentNodeId} & Certificado X.509 v2.0 (DPAPI)",
            Font = new Font("Segoe UI", 13.5f, FontStyle.Bold),
            ForeColor = HologramTheme.HologramCyan,
            Dock = DockStyle.Top,
            Height = 36,
            BackColor = HologramTheme.PanelGlass
        };
        _txtSettingsCertInfo = HologramTheme.CreateDarkTextBox(multiline: true, readOnly: true, mono: true);
        _txtSettingsCertInfo.Dock = DockStyle.Fill;

        var btnRegen = new NeonButton
        {
            Text = $"🔄 Regenerar Certificado X.509 v2.0 (CN={NodeRuntimeState.CurrentNodeId})",
            Variant = NeonButtonVariant.Primary,
            Dock = DockStyle.Bottom,
            Height = 42
        };
        btnRegen.Click += (_, _) =>
        {
            NodeCertificateService.Initialize(forceRegenerate: true);
            RefreshSettingsStats();
            MessageBox.Show(this,
                $"Nuevo certificado X.509 RSA-2048 generado con vigencia de 365 días para:\n{NodeCertificateService.Subject}",
                $"Certificado X.509 v2.0 — {NodeRuntimeState.CurrentNodeId}", MessageBoxButtons.OK, MessageBoxIcon.Information);
        };

        var certSpacer = new Panel { Dock = DockStyle.Bottom, Height = 12, BackColor = HologramTheme.PanelGlass };
        leftCard.Controls.Add(_txtSettingsCertInfo);
        leftCard.Controls.Add(certSpacer);
        leftCard.Controls.Add(btnRegen);
        leftCard.Controls.Add(lblCertTitle);

        var rightCard = new GlassPanel { Dock = DockStyle.Fill, CornerRadius = 18, Padding = new Padding(20), Margin = new Padding(10, 0, 0, 0) };
        var lblDbTitle = new Label
        {
            Text = "SQLite (TOFU / Anti-Replay) & Diagnóstico Visual",
            Font = new Font("Segoe UI", 13.5f, FontStyle.Bold),
            ForeColor = HologramTheme.HologramViolet,
            Dock = DockStyle.Top,
            Height = 36,
            BackColor = HologramTheme.PanelGlass
        };

        _lblSettingsDbStats = new Label
        {
            Dock = DockStyle.Top,
            Height = 175,
            Font = HologramTheme.FontMono(9.2f),
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
            $"Nodo Activo        : {NodeRuntimeState.CurrentNodeId} (Equipo {NodeRuntimeState.TeamNumber:D2})\r\n" +
            $"Algoritmos Dueño   : {string.Join(", ", NodeRuntimeState.OwnedAlgorithms)}\r\n" +
            $"Operador Logueado  : {_userFullName} ({_currentUser.NombreUsuario})\r\n" +
            $"API v2.0 Embebida  : http://0.0.0.0:{NodeRuntimeState.ApiPort}\r\n" +
            $"Beacon UDP 5099    : Activo (CC-BEACON cada 30s)\r\n" +
            $"---------------------------------------------------\r\n" +
            $"X.509 Subject      : {cert.Subject}\r\n" +
            $"X.509 SHA-256 (64) : {NodeCertificateService.GetThumbprintSha256Hex()}\r\n" +
            $"Serial (>=64 bits) : {cert.SerialNumber}\r\n" +
            $"Firma Estándar     : RSA-PSS-SHA256 (MGF1, sal 32B)\r\n" +
            $"Vigencia (365 días): {cert.NotBefore.ToUniversalTime():yyyy-MM-dd} a {cert.NotAfter.ToUniversalTime():yyyy-MM-dd} UTC";

        using var db = new AppDbContext();
        int uCount = db.Usuarios.Count();
        int rCount = db.RegistrosCifrados.Count();
        int sCount = db.SolicitudesEntrantes.Count();
        int sPend = db.SolicitudesEntrantes.Count(s => s.Estado == "Pendiente");
        int tCount = db.TrustedPeers.Count();
        int spCount = db.SeenPackets.Count();

        _lblSettingsDbStats.Text =
            $"Archivo SQLite     : {AppDbContext.DatabasePath}\r\n" +
            $"Tabla Usuarios     : {uCount} integrante(s) (PBKDF2-SHA256)\r\n" +
            $"Tabla Consultas    : {rCount} registro(s) local(es)\r\n" +
            $"Tabla Solicitudes  : {sCount} total ({sPend} pendiente(s))\r\n" +
            $"Tabla TrustedPeers : {tCount} nodo(s) en directorio TOFU\r\n" +
            $"Tabla SeenPackets  : {spCount} paquete(s) Anti-Replay";
    }
}
