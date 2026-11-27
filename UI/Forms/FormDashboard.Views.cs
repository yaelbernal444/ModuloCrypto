using Microsoft.EntityFrameworkCore;
using ModuloCrypto.Core.Contracts;
using ModuloCrypto.Core.Data;
using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using ModuloCrypto.Network.Shared;
using ModuloCrypto.Network.V1;
using ModuloCrypto.Network.V2;
using ModuloCrypto.Security;
using ModuloCrypto.UI.Controls;
using ModuloCrypto.UI.Theme;
using System.Drawing;
using System.Text.Json;
using System.Windows.Forms;

namespace ModuloCrypto.UI.Forms;

public partial class FormDashboard
{
    // Solicitudes (Bandeja + Bitácora de Red)
    private DataGridView _gridSolicitudes = null!;
    private TextBox _txtNetworkEventLog = null!;

    // Consultas (Historial)
    private DataGridView _gridConsultas = null!;
    private TextBox _txtSearchHistory = null!;
    private ComboBox _cmbFilterOrigin = null!;

    // Red de Nodos (IP Activa / TOFU / UDP 5099)
    private DataGridView _gridPeers = null!;
    private TextBox _txtEditPeerIp = null!;
    private TextBox _txtEditPeerPort = null!;
    private Label _lblActiveIpEndpoint = null!;
    private Label _lblActiveIpInterface = null!;
    private ComboBox _cmbActiveAdapter = null!;
    private bool _suppressAdapterComboEvent;

    // Ajustes
    private Label _lblSettingsDbStats = null!;
    private TextBox _txtSettingsCertInfo = null!;

    /// <summary>
    /// Crea el recuadro de IP Activa exclusivamente para la vista Red de Nodos.
    /// </summary>
    private GlassPanel CreateNetworkViewIpCardControl()
    {
        var ipCard = new GlassPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            MinimumSize = new Size(0, 56),
            CornerRadius = 12,
            NeonBorderGlow = true,
            BorderColor = HologramTheme.HologramCyan,
            FillColorTop = Color.FromArgb(24, 21, 44),
            FillColorBottom = HologramTheme.PanelGlass,
            Padding = new Padding(12, 8, 12, 8),
            Margin = new Padding(0, 0, 0, 8)
        };

        var flow = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            AutoSize = true,
            WrapContents = true,
            FlowDirection = FlowDirection.LeftToRight,
            BackColor = Color.Transparent,
            Margin = new Padding(0)
        };

        var lblVersionBadge = new Label
        {
            Text = $" {_runtime.VersionBadgeText} ",
            Font = new Font("Cascadia Mono", 8.8f, FontStyle.Bold),
            ForeColor = Color.White,
            BackColor = NodeRuntimeState.IsV2 ? HologramTheme.AccentStart : Color.FromArgb(65, 110, 215),
            AutoSize = true,
            Padding = new Padding(8, 5, 8, 5),
            Margin = new Padding(0, 4, 12, 4),
            TextAlign = ContentAlignment.MiddleCenter
        };

        var lblCaption = new Label
        {
            Text = "MI IP ACTIVA:",
            Font = new Font("Segoe UI", 8.6f, FontStyle.Bold),
            ForeColor = HologramTheme.TextSecondary,
            AutoSize = true,
            Margin = new Padding(0, 8, 6, 4),
            BackColor = Color.Transparent
        };

        _lblActiveIpEndpoint = new Label
        {
            Text = $"{NodeRuntimeState.LocalIpAddress}:{NodeRuntimeState.ApiPort}",
            Font = new Font("Cascadia Mono", 12f, FontStyle.Bold),
            ForeColor = HologramTheme.HologramCyan,
            AutoSize = true,
            Margin = new Padding(0, 3, 10, 4),
            BackColor = Color.Transparent
        };

        _lblActiveIpInterface = new Label
        {
            Text = $"[{NodeRuntimeState.ActiveInterfaceName}]",
            Font = new Font("Segoe UI", 8.8f, FontStyle.Bold),
            ForeColor = NodeRuntimeState.IsLoopbackFallback ? HologramTheme.Warning : HologramTheme.Success,
            AutoSize = true,
            Margin = new Padding(0, 7, 12, 4),
            BackColor = Color.Transparent
        };

        _cmbActiveAdapter = new ComboBox
        {
            Size = new Size(215, 28),
            Font = new Font("Cascadia Mono", 8.4f, FontStyle.Bold),
            Margin = new Padding(0, 4, 10, 4)
        };
        HologramTheme.StyleComboBox(_cmbActiveAdapter, HologramTheme.HologramCyan);
        _cmbActiveAdapter.SelectedIndexChanged += async (_, _) =>
        {
            if (_suppressAdapterComboEvent) return;
            if (_cmbActiveAdapter.SelectedItem is LocalNetworkEndpoint ep)
            {
                NetworkAddressService.SelectActiveEndpoint(ep.Ipv4Address);
                RefreshActiveIpCardUi();
                await _runtime.AnnouncePresenceAsync();
            }
        };

        var btnCopyIp = new NeonButton
        {
            Text = "📋 Copiar IP",
            Variant = NeonButtonVariant.Cyan,
            CornerRadius = 8,
            Margin = new Padding(0, 2, 8, 2)
        };
        btnCopyIp.FitToText(minWidth: 118, height: 32);
        btnCopyIp.Click += async (_, _) =>
        {
            string epText = $"{NodeRuntimeState.LocalIpAddress}:{NodeRuntimeState.ApiPort}";
            Clipboard.SetText(epText);
            btnCopyIp.Text = "✓ Copiada";
            btnCopyIp.Variant = NeonButtonVariant.Success;
            btnCopyIp.FitToText(minWidth: 118, height: 32);
            await Task.Delay(1300);
            if (!btnCopyIp.IsDisposed)
            {
                btnCopyIp.Text = "📋 Copiar IP";
                btnCopyIp.Variant = NeonButtonVariant.Cyan;
                btnCopyIp.FitToText(minWidth: 118, height: 32);
            }
        };

        var btnRefreshIp = new NeonButton
        {
            Text = "↻ Refrescar IP",
            Variant = NeonButtonVariant.Secondary,
            CornerRadius = 8,
            Margin = new Padding(0, 2, 4, 2)
        };
        btnRefreshIp.FitToText(minWidth: 128, height: 32);
        btnRefreshIp.Click += async (_, _) =>
        {
            btnRefreshIp.Enabled = false;
            NetworkAddressService.RefreshRuntimePrimaryEndpoint();
            RefreshActiveIpCardUi();
            await _runtime.AnnouncePresenceAsync();
            RefreshNetworkGrid();
            btnRefreshIp.Enabled = true;
        };

        flow.Controls.AddRange(new Control[]
        {
            lblVersionBadge,
            lblCaption,
            _lblActiveIpEndpoint,
            _lblActiveIpInterface,
            _cmbActiveAdapter,
            btnCopyIp,
            btnRefreshIp
        });

        ipCard.Controls.Add(flow);
        return ipCard;
    }

    private void RefreshActiveIpCardUi()
    {
        var endpoints = NetworkAddressService.GetAvailableIpv4Endpoints();
        string endpointDisplay = $"{NodeRuntimeState.LocalIpAddress}:{NodeRuntimeState.ApiPort}";
        string ifaceDisplay = NodeRuntimeState.IsLoopbackFallback
            ? "[Sin red LAN]"
            : $"[{NodeRuntimeState.ActiveInterfaceName} • Bcast {NodeRuntimeState.SubnetBroadcastAddress}]";

        if (_lblActiveIpEndpoint != null)
            _lblActiveIpEndpoint.Text = endpointDisplay;

        if (_lblActiveIpInterface != null)
        {
            _lblActiveIpInterface.Text = ifaceDisplay;
            _lblActiveIpInterface.ForeColor = NodeRuntimeState.IsLoopbackFallback ? HologramTheme.Warning : HologramTheme.Success;
        }

        if (_cmbActiveAdapter != null)
        {
            _suppressAdapterComboEvent = true;
            try
            {
                _cmbActiveAdapter.Items.Clear();
                int selIdx = 0;
                for (int i = 0; i < endpoints.Count; i++)
                {
                    _cmbActiveAdapter.Items.Add(endpoints[i]);
                    if (string.Equals(endpoints[i].Ipv4Address, NodeRuntimeState.LocalIpAddress, StringComparison.OrdinalIgnoreCase))
                        selIdx = i;
                }
                if (_cmbActiveAdapter.Items.Count > 0)
                    _cmbActiveAdapter.SelectedIndex = selIdx;
                _cmbActiveAdapter.Visible = endpoints.Count > 1;
            }
            finally
            {
                _suppressAdapterComboEvent = false;
            }
        }

        var selfPeer = NodeRuntimeState.NetworkPeers.FirstOrDefault(p =>
            string.Equals(p.NodeId, NodeRuntimeState.CurrentNodeId, StringComparison.OrdinalIgnoreCase));
        if (selfPeer != null)
        {
            selfPeer.IpAddress = NodeRuntimeState.LocalIpAddress;
            selfPeer.Port = NodeRuntimeState.ApiPort;
        }
    }

    private void HandleNetworkEndpointsChangedEvent(LocalNetworkEndpoint ep)
    {
        if (IsHandleCreated && !IsDisposed)
        {
            BeginInvoke(async () =>
            {
                RefreshActiveIpCardUi();
                RefreshNetworkGrid();
                RefreshTargetPeerCombo();
                await _runtime.AnnouncePresenceAsync();
            });
        }
    }

    private void BuildSolicitudesView()
    {
        var panel = new Panel { Dock = DockStyle.Fill, BackColor = HologramTheme.BackgroundBase, Visible = false };
        _views["inbox"] = panel;
        _viewHost.Controls.Add(panel);

        var card = new GlassPanel { Dock = DockStyle.Fill, CornerRadius = 18, Padding = new Padding(18) };

        var header = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            ColumnCount = 1,
            RowCount = 2,
            BackColor = HologramTheme.PanelGlass
        };
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
        header.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        header.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        var titleStack = new Panel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            BackColor = HologramTheme.PanelGlass
        };
        var lblTitle = new Label
        {
            Text = $"Solicitudes Entrantes (.ZIP v{NodeRuntimeState.ProtocolVersion}) — {NodeRuntimeState.CurrentNodeId}",
            Font = new Font("Segoe UI", 14f, FontStyle.Bold),
            ForeColor = HologramTheme.TextPrimary,
            Dock = DockStyle.Top,
            AutoSize = true,
            BackColor = HologramTheme.PanelGlass
        };
        string subInbox = NodeRuntimeState.IsV2
            ? "Validación de 14 pasos: 3 archivos planos, Anti-ZIP-Bomb, RSA-PSS-SHA256 (11 campos), TOFU y Anti-Replay"
            : "Modo Híbrido v1.0: soporte de 5 archivos (manifest.json, datos.enc, payload.bin, certificado.pem, root_cert.cer) y descifrado remoto";

        var lblSub = new Label
        {
            Text = subInbox,
            Font = HologramTheme.FontBody(8.8f),
            ForeColor = HologramTheme.TextSecondary,
            Dock = DockStyle.Top,
            AutoSize = true,
            Padding = new Padding(0, 2, 0, 2),
            BackColor = HologramTheme.PanelGlass
        };
        titleStack.Controls.Add(lblSub);
        titleStack.Controls.Add(lblTitle);

        var btnFlow = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            WrapContents = true,
            FlowDirection = FlowDirection.LeftToRight,
            Padding = new Padding(0, 8, 0, 4),
            BackColor = HologramTheme.PanelGlass
        };

        var btnAccept = new NeonButton { Text = "✓ Aceptar y Descifrar", Variant = NeonButtonVariant.Success, Margin = new Padding(0, 2, 8, 2) };
        btnAccept.FitToText(minWidth: 165, height: 36);
        btnAccept.Click += async (_, _) =>
        {
            btnAccept.Enabled = false;
            try { await HandleAcceptAndDecryptSolicitudAsync(); }
            finally { if (!btnAccept.IsDisposed) btnAccept.Enabled = true; }
        };

        var btnReject = new NeonButton { Text = "✕ Rechazar", Variant = NeonButtonVariant.Danger, Margin = new Padding(0, 2, 8, 2) };
        btnReject.FitToText(minWidth: 105, height: 36);
        btnReject.Click += (_, _) => HandleUpdateSolicitudEstado("Rechazada");

        var btnForward = new NeonButton
        {
            Text = NodeRuntimeState.IsV2 ? "↪ Reenviar v2.0" : "↪ Reenviar v1.0",
            Variant = NeonButtonVariant.Primary,
            Margin = new Padding(0, 2, 8, 2)
        };
        btnForward.FitToText(minWidth: 136, height: 36);
        btnForward.Click += async (_, _) =>
        {
            btnForward.Enabled = false;
            try { await HandleForwardSelectedSolicitudAsync(); }
            finally { if (!btnForward.IsDisposed) btnForward.Enabled = true; }
        };

        var btnImportZip = new NeonButton { Text = "📥 Importar .ZIP", Variant = NeonButtonVariant.Cyan, Margin = new Padding(0, 2, 8, 2) };
        btnImportZip.FitToText(minWidth: 132, height: 36);
        btnImportZip.Click += (_, _) => HandleImportZipToInbox();

        var btnCleanOrphans = new NeonButton { Text = "🧹 Limpiar Huérfanas", Variant = NeonButtonVariant.Secondary, Margin = new Padding(0, 2, 8, 2) };
        btnCleanOrphans.FitToText(minWidth: 158, height: 36);
        btnCleanOrphans.Click += (_, _) => HandleCleanOrphanSolicitudes();

        var btnDeleteSolicitud = new NeonButton { Text = "🗑 Eliminar", Variant = NeonButtonVariant.Danger, Margin = new Padding(0, 2, 8, 2) };
        btnDeleteSolicitud.FitToText(minWidth: 108, height: 36);
        btnDeleteSolicitud.Click += (_, _) => HandleDeleteSelectedSolicitud();

        var btnRefresh = new NeonButton { Text = "↻ Actualizar", Variant = NeonButtonVariant.Secondary, Margin = new Padding(0, 2, 8, 2) };
        btnRefresh.FitToText(minWidth: 110, height: 36);
        btnRefresh.Click += (_, _) =>
        {
            RefreshSolicitudesGrid();
            RefreshPendingSolicitudesBadge();
            RefreshConsultasGrid();
            RefreshNetworkLogBox();
        };

        btnFlow.Controls.AddRange(new Control[]
        {
            btnAccept,
            btnReject,
            btnForward,
            btnImportZip,
            btnCleanOrphans,
            btnDeleteSolicitud,
            btnRefresh
        });

        header.Controls.Add(titleStack, 0, 0);
        header.Controls.Add(btnFlow, 0, 1);

        // Panel compacto inferior (95 px) con Bitácora en tiempo real de peticiones aceptadas y rechazadas
        var logPanel = new GlassPanel
        {
            Dock = DockStyle.Bottom,
            Height = 96,
            CornerRadius = 12,
            BorderColor = HologramTheme.BorderSubtle,
            FillColorTop = Color.FromArgb(16, 14, 30),
            FillColorBottom = Color.FromArgb(12, 10, 24),
            Padding = new Padding(10, 6, 10, 6)
        };

        var logTopBar = new Panel
        {
            Dock = DockStyle.Top,
            Height = 20,
            BackColor = Color.Transparent
        };

        var lblLogCaption = new Label
        {
            Text = "📡 Registro de Red (Últimos Eventos / Rechazos):",
            Font = new Font("Segoe UI", 8.6f, FontStyle.Bold),
            ForeColor = HologramTheme.HologramCyan,
            Dock = DockStyle.Left,
            AutoSize = true,
            BackColor = Color.Transparent
        };

        var lblClearLog = new Label
        {
            Text = "[Limpiar log]",
            Font = new Font("Cascadia Mono", 8f, FontStyle.Underline),
            ForeColor = HologramTheme.TextSecondary,
            Dock = DockStyle.Right,
            AutoSize = true,
            Cursor = Cursors.Hand,
            BackColor = Color.Transparent
        };
        lblClearLog.Click += (_, _) =>
        {
            NodeRuntimeState.ClearNetworkLogs();
            RefreshNetworkLogBox();
        };

        logTopBar.Controls.Add(lblClearLog);
        logTopBar.Controls.Add(lblLogCaption);

        _txtNetworkEventLog = HologramTheme.CreateDarkTextBox(multiline: true, readOnly: true, mono: true);
        _txtNetworkEventLog.Dock = DockStyle.Fill;
        _txtNetworkEventLog.Font = new Font("Cascadia Mono", 8.4f);
        _txtNetworkEventLog.ScrollBars = ScrollBars.Vertical;
        _txtNetworkEventLog.WordWrap = false;
        _txtNetworkEventLog.BackColor = Color.FromArgb(12, 10, 24);
        _txtNetworkEventLog.ForeColor = HologramTheme.TextPrimary;

        logPanel.Controls.Add(_txtNetworkEventLog);
        logPanel.Controls.Add(logTopBar);

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

        var gridWrap = new Panel { Dock = DockStyle.Fill, Padding = new Padding(0, 8, 0, 8), BackColor = HologramTheme.PanelGlass };
        gridWrap.Controls.Add(_gridSolicitudes);

        card.Controls.Add(gridWrap);
        card.Controls.Add(logPanel);
        card.Controls.Add(header);
        panel.Controls.Add(card);

        RefreshNetworkLogBox();
    }

    private void RefreshNetworkLogBox()
    {
        if (_txtNetworkEventLog == null || _txtNetworkEventLog.IsDisposed) return;
        var logs = NodeRuntimeState.GetNetworkLogsSnapshot();
        if (logs.Count == 0)
        {
            _txtNetworkEventLog.Text = $"[{DateTime.Now:HH:mm:ss}] Escuchando peticiones en {NodeRuntimeState.LocalIpAddress}:{NodeRuntimeState.ApiPort} (/api/requests/receive, /api/crypto/forward, /api/crypto/inverse)...";
            return;
        }
        _txtNetworkEventLog.Text = string.Join(Environment.NewLine, logs);
        _txtNetworkEventLog.SelectionStart = _txtNetworkEventLog.TextLength;
        _txtNetworkEventLog.ScrollToCaret();
    }

    private void AppendOrRefreshNetworkLogLine(string logLine)
    {
        if (_txtNetworkEventLog == null || _txtNetworkEventLog.IsDisposed) return;
        RefreshNetworkLogBox();
    }

    private void RefreshSolicitudesGrid()
    {
        if (_gridSolicitudes == null) return;
        using var db = new AppDbContext();
        var list = db.SolicitudesEntrantes
            .AsNoTracking()
            .OrderByDescending(s => s.FechaRecepcion)
            .ThenByDescending(s => s.Id)
            .ToList();

        var rows = list
            .Select(s => new
            {
                s.Id,
                PacketId = s.PacketId.Length > 12 ? s.PacketId.Substring(0, 12) + "..." : s.PacketId,
                SourceNode = s.NodoOrigen,
                s.IpOrigen,
                s.NombreZip,
                Algoritmo = s.AlgoritmoCodigo,
                FirmaX509 = s.FirmaX509Valida ? "✓ X.509 Válida" : "✕ Inválida / Sin firma",
                s.Estado,
                Recibido = s.FechaRecepcion.ToString("yyyy-MM-dd HH:mm:ss")
            })
            .ToList();

        _gridSolicitudes.DataSource = null;
        _gridSolicitudes.DataSource = rows;
    }

    private void HandleCleanOrphanSolicitudes()
    {
        try
        {
            using var db = new AppDbContext();
            var pendingList = db.SolicitudesEntrantes
                .Where(s => s.Estado == "Pendiente")
                .ToList();

            var orphans = pendingList
                .Where(s => string.IsNullOrWhiteSpace(s.RutaZipTemporal) || !File.Exists(s.RutaZipTemporal))
                .ToList();

            if (orphans.Count == 0)
            {
                MessageBox.Show(this,
                    "No se encontraron solicitudes pendientes huérfanas (todos los paquetes .zip pendientes existen en disco).",
                    "Limpiar Solicitudes Huérfanas",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                return;
            }

            var choice = MessageBox.Show(this,
                $"Se detectaron {orphans.Count} solicitud(es) en estado 'Pendiente' cuyo archivo .zip temporal ya no existe en disco.\n\n" +
                $"• Pulsa [Sí] para ELIMINARLAS permanentemente de SolicitudesEntrantes.\n" +
                $"• Pulsa [No] para marcarlas como 'Rechazada'.\n" +
                $"• Pulsa [Cancelar] para no hacer cambios.",
                "Limpiar Solicitudes Huérfanas",
                MessageBoxButtons.YesNoCancel,
                MessageBoxIcon.Question);

            if (choice == DialogResult.Cancel) return;

            if (choice == DialogResult.Yes)
            {
                db.SolicitudesEntrantes.RemoveRange(orphans);
            }
            else
            {
                foreach (var o in orphans)
                    o.Estado = "Rechazada";
            }

            db.SaveChanges();
            RefreshSolicitudesGrid();
            RefreshPendingSolicitudesBadge();

            MessageBox.Show(this,
                choice == DialogResult.Yes
                    ? $"Se eliminaron {orphans.Count} solicitud(es) huérfana(s)."
                    : $"Se marcaron {orphans.Count} solicitud(es) huérfana(s) como 'Rechazada'.",
                "Limpieza Completada",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Error de SQLite al limpiar solicitudes huérfanas:\n{ex.Message}", "Error SQLite", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void HandleDeleteSelectedSolicitud()
    {
        if (_gridSolicitudes.SelectedRows.Count == 0) return;
        int id = Convert.ToInt32(_gridSolicitudes.SelectedRows[0].Cells["Id"].Value);

        try
        {
            using var db = new AppDbContext();
            var sol = db.SolicitudesEntrantes.Find(id);
            if (sol == null) return;

            if (MessageBox.Show(this,
                $"¿Eliminar la solicitud #{sol.Id} ({sol.NombreZip} de {sol.NodoOrigen})?",
                "Eliminar Solicitud",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question) != DialogResult.Yes)
            {
                return;
            }

            db.SolicitudesEntrantes.Remove(sol);
            db.SaveChanges();
            RefreshSolicitudesGrid();
            RefreshPendingSolicitudesBadge();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Error de SQLite al eliminar la solicitud:\n{ex.Message}", "Error SQLite", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void HandleImportZipToInbox()
    {
        using var ofd = new OpenFileDialog { Filter = $"Paquete Protocolo v{NodeRuntimeState.ProtocolVersion} (*.zip)|*.zip" };
        if (ofd.ShowDialog(this) != DialogResult.OK) return;

        try
        {
            string dir = AppDbContext.IncomingPacketsDirectory;
            Directory.CreateDirectory(dir);
            string dest = Path.Combine(dir, $"{Guid.NewGuid().ToString("N")[..6]}_{Path.GetFileName(ofd.FileName)}");

            if (NodeRuntimeState.IsV2)
            {
                var parsed = V2PacketZipService.ReadPacketZip(ofd.FileName, enforceStrictSignature: true);
                File.Copy(ofd.FileName, dest, true);

                using var db = new AppDbContext();
                var nueva = new SolicitudEntrante
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
                };
                db.SolicitudesEntrantes.Add(nueva);
                db.SaveChanges();
                NodeRuntimeState.AddNetworkLog("LOCAL", parsed.Manifest.SourceNode, "Importar .ZIP", 202, $"accepted ({parsed.Manifest.AlgorithmCode}, packetId={parsed.Manifest.PacketId})");
            }
            else
            {
                var parsed = V1PacketZipService.ReadPacketZip(ofd.FileName);
                File.Copy(ofd.FileName, dest, true);

                using var db = new AppDbContext();
                var nueva = new SolicitudEntrante
                {
                    PacketId = parsed.Manifest.PacketId,
                    NodoOrigen = parsed.Manifest.NodoRaiz,
                    IpOrigen = "Importación Local v1.0",
                    NombreZip = Path.GetFileName(ofd.FileName),
                    AlgoritmoCodigo = parsed.Manifest.AlgoritmoCodigo,
                    FirmaX509Valida = parsed.SignatureValid && parsed.IntegrityValid,
                    RutaZipTemporal = dest,
                    Estado = "Pendiente",
                    FechaRecepcion = DateTime.Now
                };
                db.SolicitudesEntrantes.Add(nueva);
                db.SaveChanges();
                NodeRuntimeState.AddNetworkLog("LOCAL", parsed.Manifest.NodoRaiz, "Importar .ZIP v1.0", 200, $"accepted ({parsed.Manifest.AlgoritmoCodigo})");
            }

            RefreshSolicitudesGrid();
            RefreshPendingSolicitudesBadge();
        }
        catch (PacketValidationException pve)
        {
            NodeRuntimeState.AddNetworkLog("LOCAL", "IMPORT", "Importar .ZIP", pve.HttpStatusCode, $"{pve.ErrorCode}: {pve.Message}");
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

    private async Task HandleForwardSelectedSolicitudAsync()
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
            string targetPeerId = _cmbTargetPeer.SelectedItem?.ToString()?.Split(' ')[0] ?? "";
            var peer = NodeRuntimeState.NetworkPeers.FirstOrDefault(p => p.NodeId == targetPeerId)
                       ?? NodeRuntimeState.NetworkPeers.First();

            if (NodeRuntimeState.IsV2)
            {
                string repackagedZip = V2PacketZipService.RepackageForForwarding(sol.RutaZipTemporal);
                var parsed = V2PacketZipService.ReadPacketZip(repackagedZip, enforceStrictSignature: true);
                var sendRes = await V2NetworkClient.SendZipPacketAsync(peer, repackagedZip, parsed.Manifest.PacketId, parsed.Manifest.PacketType);

                MessageBox.Show(this,
                    $"{sendRes.Message}\n\n" +
                    $"• Nuevo PacketId : {parsed.Manifest.PacketId}\n" +
                    $"• ProducerNode   : {parsed.Manifest.ProducerNode} (conservado)\n" +
                    $"• SourceNode     : {parsed.Manifest.SourceNode} (re-firmado)",
                    sendRes.Success ? "Reenvío Estándar v2.0 (Sección 9.6) Exitoso" : "Error en Reenvío v2.0",
                    MessageBoxButtons.OK,
                    sendRes.Success ? MessageBoxIcon.Information : MessageBoxIcon.Error);
            }
            else
            {
                var sendRes = await V1NetworkClient.SendZipPacketAsync(peer, sol.RutaZipTemporal, sol.PacketId);
                MessageBox.Show(this, sendRes.Message,
                    sendRes.Success ? "Reenvío v1.0 Exitoso" : "Error en Reenvío v1.0",
                    MessageBoxButtons.OK,
                    sendRes.Success ? MessageBoxIcon.Information : MessageBoxIcon.Error);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Error al reenviar paquete:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
        if (sol == null)
        {
            RefreshSolicitudesGrid();
            RefreshPendingSolicitudesBadge();
            return;
        }

        // Si el archivo .zip temporal ya no existe en disco, intentar repararlo desde IncomingPacketsDirectory
        if (string.IsNullOrWhiteSpace(sol.RutaZipTemporal) || !File.Exists(sol.RutaZipTemporal))
        {
            string fileName = Path.GetFileName(sol.RutaZipTemporal ?? sol.NombreZip ?? "");
            string candidate = !string.IsNullOrWhiteSpace(fileName)
                ? Path.Combine(AppDbContext.IncomingPacketsDirectory, fileName)
                : string.Empty;

            if (!string.IsNullOrWhiteSpace(candidate) && File.Exists(candidate))
            {
                sol.RutaZipTemporal = candidate;
                db.SaveChanges();
            }
            else
            {
                var action = MessageBox.Show(this,
                    $"No se encontró en disco el archivo .zip temporal de la solicitud #{sol.Id} ({sol.NombreZip} de {sol.NodoOrigen}):\n" +
                    $"Ruta esperada: {sol.RutaZipTemporal}\n\n" +
                    $"• Pulsa [Sí] para ELIMINAR esta solicitud huérfana de SolicitudesEntrantes.\n" +
                    $"• Pulsa [No] para marcarla como 'Rechazada'.\n" +
                    $"• Pulsa [Cancelar] para conservarla sin cambios.",
                    "Archivo .ZIP Temporal No Encontrado",
                    MessageBoxButtons.YesNoCancel,
                    MessageBoxIcon.Warning);

                if (action == DialogResult.Yes)
                {
                    db.SolicitudesEntrantes.Remove(sol);
                    db.SaveChanges();
                }
                else if (action == DialogResult.No)
                {
                    sol.Estado = "Rechazada";
                    db.SaveChanges();
                }

                RefreshSolicitudesGrid();
                RefreshPendingSolicitudesBadge();
                return;
            }
        }

        if (NodeRuntimeState.IsV2)
        {
            await AcceptAndDecryptSolicitudV2Async(db, sol);
        }
        else
        {
            await AcceptAndDecryptSolicitudV1Async(db, sol);
        }
    }

    private async Task AcceptAndDecryptSolicitudV2Async(AppDbContext db, SolicitudEntrante sol)
    {
        try
        {
            var parsed = V2PacketZipService.ReadPacketZip(sol.RutaZipTemporal, enforceStrictSignature: true);
            string? secretKey = null;
            string pubJson = JsonSerializer.Serialize(parsed.Manifest.PublicParameters);

            string lookupKeyId = parsed.Manifest.KeyRef?.KeyId ?? parsed.Manifest.PacketId;
            var localMatch = db.RegistrosCifrados.FirstOrDefault(r =>
                r.PacketId == lookupKeyId || r.PacketId == parsed.Manifest.PacketId);

            if (localMatch != null && !string.IsNullOrWhiteSpace(localMatch.LlaveSecretaBase64))
            {
                secretKey = localMatch.LlaveSecretaBase64;
                if (string.IsNullOrWhiteSpace(pubJson) || pubJson == "{}")
                    pubJson = localMatch.ParametrosPublicosJson;
            }

            if (string.IsNullOrWhiteSpace(secretKey) &&
                !string.Equals(parsed.Manifest.ProducerNode, NodeRuntimeState.CurrentNodeId, StringComparison.OrdinalIgnoreCase))
            {
                var producerPeer = NodeRuntimeState.NetworkPeers.FirstOrDefault(p =>
                    string.Equals(p.NodeId, parsed.Manifest.ProducerNode, StringComparison.OrdinalIgnoreCase) && p.IsOnline);
                if (producerPeer != null && !producerPeer.HasThumbprintMismatch)
                {
                    var (invOk, plainFromRemote, _, _) = await V2NetworkClient.CallRemoteInverseAsync(
                        producerPeer,
                        parsed.Manifest.AlgorithmCode,
                        parsed.Manifest.PacketId,
                        parsed.PayloadBytes,
                        parsed.Manifest.PublicParameters,
                        keyId: lookupKeyId);

                    if (invOk && plainFromRemote != null)
                    {
                        FinalizeAcceptedSolicitud(
                            db,
                            sol,
                            parsed.Manifest.PacketId,
                            parsed.Manifest.OriginalFileName,
                            parsed.Manifest.OriginalExtension,
                            parsed.PayloadBytes,
                            parsed.Manifest.AlgorithmCode,
                            pubJson,
                            string.Empty,
                            $"keyRef://{parsed.Manifest.ProducerNode}/{lookupKeyId}",
                            parsed.Manifest.ProducerNode,
                            parsed.Manifest.ManifestSignatureBase64,
                            new List<string> { parsed.Manifest.ProducerNode, parsed.Manifest.SourceNode, NodeRuntimeState.CurrentNodeId }.Distinct().ToList(),
                            parsed.SignatureValid && parsed.IntegrityValid,
                            hasSignature: true,
                            preDecryptedBytes: plainFromRemote);
                        return;
                    }
                }
            }

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

            string keyRefDisplay = parsed.Manifest.KeyRef != null
                ? parsed.Manifest.KeyRef.KeyId
                : V2FormatValidators.BuildKeyId(parsed.Manifest.ProducerNode, parsed.Manifest.PacketId);

            FinalizeAcceptedSolicitud(
                db,
                sol,
                parsed.Manifest.PacketId,
                parsed.Manifest.OriginalFileName,
                parsed.Manifest.OriginalExtension,
                parsed.PayloadBytes,
                parsed.Manifest.AlgorithmCode,
                pubJson,
                secretKey,
                keyRefDisplay,
                parsed.Manifest.ProducerNode,
                parsed.Manifest.ManifestSignatureBase64,
                hops,
                parsed.SignatureValid && parsed.IntegrityValid,
                hasSignature: true,
                requestId: parsed.Manifest.RequestId);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Error al procesar solicitud v2.0:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private async Task AcceptAndDecryptSolicitudV1Async(AppDbContext db, SolicitudEntrante sol)
    {
        try
        {
            var parsed = V1PacketZipService.ReadPacketZip(sol.RutaZipTemporal);
            string? secretKey = null;
            string pubJson = parsed.Manifest.ParametrosPublicosJson;

            var localMatch = db.RegistrosCifrados.FirstOrDefault(r => r.PacketId == parsed.Manifest.PacketId);
            if (localMatch != null && !string.IsNullOrWhiteSpace(localMatch.LlaveSecretaBase64))
            {
                secretKey = localMatch.LlaveSecretaBase64;
                if (string.IsNullOrWhiteSpace(pubJson) || pubJson == "{}")
                    pubJson = localMatch.ParametrosPublicosJson;
            }

            if (string.IsNullOrWhiteSpace(secretKey) &&
                !string.IsNullOrWhiteSpace(parsed.Manifest.LinkDescifradoRemoto) &&
                parsed.Manifest.LinkDescifradoRemoto.StartsWith("http", StringComparison.OrdinalIgnoreCase))
            {
                var remote = await V1NetworkClient.RequestRemoteKeyAsync(parsed.Manifest.LinkDescifradoRemoto);
                if (remote.Success && !string.IsNullOrWhiteSpace(remote.LlaveSecretaBase64))
                {
                    secretKey = remote.LlaveSecretaBase64;
                    if (string.IsNullOrWhiteSpace(pubJson) || pubJson == "{}")
                        pubJson = remote.ParametrosPublicosJson;
                }
            }

            if (string.IsNullOrWhiteSpace(secretKey))
            {
                string? manualKey = PromptExternalPassphraseModal(
                    parsed.Manifest.AlgoritmoCodigo,
                    parsed.Manifest.NodoRaiz,
                    parsed.Manifest.SourceIp,
                    parsed.SignatureValid);
                if (manualKey == null)
                    return;
                secretKey = manualKey;
            }

            var hops = parsed.Manifest.RutaSaltos ?? new List<string> { parsed.Manifest.NodoRaiz };
            if (!hops.Contains(NodeRuntimeState.CurrentNodeId))
                hops.Add(NodeRuntimeState.CurrentNodeId);

            _relayRootSignatureBase64 = parsed.Manifest.FirmaRaizBase64;
            _relayRootCertBase64 = parsed.Manifest.CertificadoRaizBase64;
            _relayRemoteDecryptLink = parsed.Manifest.LinkDescifradoRemoto;

            FinalizeAcceptedSolicitud(
                db,
                sol,
                parsed.Manifest.PacketId,
                parsed.Manifest.NombreArchivo,
                parsed.Manifest.Extension,
                parsed.PayloadBytes,
                parsed.Manifest.AlgoritmoCodigo,
                pubJson,
                secretKey,
                parsed.Manifest.LinkDescifradoRemoto,
                parsed.Manifest.NodoRaiz,
                parsed.Manifest.FirmaRaizBase64,
                hops,
                parsed.SignatureValid && parsed.IntegrityValid,
                parsed.HasSignature);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Error al procesar solicitud v1.0:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void FinalizeAcceptedSolicitud(
        AppDbContext db,
        SolicitudEntrante sol,
        string packetId,
        string fileName,
        string extension,
        byte[] cipherBytes,
        string algCode,
        string pubJson,
        string secretKey,
        string keyLink,
        string rootNode,
        string rootSig,
        List<string> hops,
        bool sigValid,
        bool hasSignature,
        byte[]? preDecryptedBytes = null,
        string? requestId = null)
    {
        _relayProducerNode = rootNode;
        _relayHopHistory = new List<string>(hops);
        _relaySourceZipPath = sol.RutaZipTemporal;
        _isFromNetworkUntrusted = true;

        var ctx = new DecryptionContext(
            PacketId: packetId,
            RequestId: requestId,
            OriginalFileName: fileName,
            OriginalExtension: extension);

        bool decryptSucceeded = preDecryptedBytes != null;
        string currentKeyAttempt = secretKey;

        // Si aún no viene pre-descifrado por inverse remoto, probar descifrar con posibilidad de reintentar clave o conservar el paquete recibido en Consultas
        while (!decryptSucceeded)
        {
            decryptSucceeded = ExecuteDecryption(
                algCode,
                cipherBytes,
                currentKeyAttempt,
                pubJson,
                ctx,
                showErrorMessageBox: false,
                out string? decErr);

            if (decryptSucceeded)
                break;

            var retryChoice = MessageBox.Show(this,
                $"No fue posible descifrar el paquete {packetId} ({algCode}) con la clave ingresada:\n\n" +
                $"Detalle criptográfico:\n{decErr}\n\n" +
                $"• Pulsa [Sí] para REINTENTAR ingresando otra clave/llave.\n" +
                $"• Pulsa [No] para GUARDAR el paquete cifrado en Consultas (como 'Recibido') y marcar la solicitud como 'Aceptada'.\n" +
                $"• Pulsa [Cancelar] para dejar la solicitud en estado 'Pendiente'.",
                "Fallo de Descifrado — Reintentar o Guardar en Consultas",
                MessageBoxButtons.YesNoCancel,
                MessageBoxIcon.Warning);

            if (retryChoice == DialogResult.Cancel)
            {
                RefreshSolicitudesGrid();
                RefreshPendingSolicitudesBadge();
                return;
            }

            if (retryChoice == DialogResult.No)
            {
                break;
            }

            string? newManualKey = PromptExternalPassphraseModal(
                algCode,
                rootNode,
                sol.NodoOrigen,
                sigValid);

            if (newManualKey == null)
            {
                RefreshSolicitudesGrid();
                RefreshPendingSolicitudesBadge();
                return;
            }

            currentKeyAttempt = newManualKey;
        }

        try
        {
            var registroRecibido = new RegistroCifrado
            {
                UsuarioId = _currentUser.Id,
                PacketId = packetId,
                NombreArchivo = fileName,
                Extension = extension,
                BytesCifrados = Convert.ToBase64String(cipherBytes),
                AlgoritmoCodigo = algCode,
                ParametrosPublicosJson = pubJson,
                LlaveSecretaBase64 = currentKeyAttempt,
                LinkDescifradoRemoto = keyLink,
                NodoRaiz = rootNode,
                FirmaRaizBase64 = rootSig,
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
            SelectAlgorithmInCombo(registroRecibido.AlgoritmoCodigo);
            UpdateMetadataPanel(registroRecibido, sigValid, hasSignature);

            RefreshSolicitudesGrid();
            RefreshPendingSolicitudesBadge();
            RefreshConsultasGrid();

            SwitchView("dashboard");

            if (preDecryptedBytes != null)
            {
                _currentBytes = preDecryptedBytes;
                _isShowingEncrypted = false;
                _hologram.TriggerDecryptAnimation(algCode);
                RenderCurrentBytesInViewer();
            }
            else if (!decryptSucceeded)
            {
                _currentBytes = cipherBytes;
                _isShowingEncrypted = true;
                _hologram.TriggerEncryptAnimation(algCode);
                RenderCurrentBytesInViewer();
            }
        }
        catch (Exception sqlEx)
        {
            MessageBox.Show(this,
                $"Error exacto de SQLite al guardar el registro recibido en Consultas:\n{sqlEx.Message}",
                "Error SQLite",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
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
            Text = $"Clave de Descifrado de Paquete v{NodeRuntimeState.ProtocolVersion}",
            FormBorderStyle = FormBorderStyle.None,
            StartPosition = FormStartPosition.CenterParent,
            Size = new Size(540, 290),
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
            Padding = new Padding(26)
        };

        var lblTitle = new Label
        {
            Text = $"Descifrar Paquete v{NodeRuntimeState.ProtocolVersion} ({algCode})",
            Font = new Font("Segoe UI", 14f, FontStyle.Bold),
            ForeColor = HologramTheme.HologramCyan,
            Location = new Point(26, 20),
            Size = new Size(488, 30),
            BackColor = HologramTheme.PanelGlass
        };

        string sigNote = sigValid ? "✓ Firma X.509 verificada" : "⚠ Firma no verificada";
        var lblSub = new Label
        {
            Text = $"Origen: {producerNode} • Emisor: {sourceNode} • {sigNote}\nIngresa la clave o llave Base64 para descifrar:",
            Font = new Font("Segoe UI", 9.2f),
            ForeColor = HologramTheme.TextSecondary,
            Location = new Point(26, 54),
            Size = new Size(488, 46),
            BackColor = HologramTheme.PanelGlass
        };

        var txtKey = HologramTheme.CreateDarkTextBox();
        txtKey.Location = new Point(26, 110);
        txtKey.Size = new Size(488, 34);
        txtKey.Font = new Font("Cascadia Mono", 10.5f);
        txtKey.Text = defaultKey;

        var lblHint = new Label
        {
            Text = "Las llaves nunca viajan en texto claro dentro de manifest.json.",
            Font = new Font("Segoe UI", 8.4f),
            ForeColor = HologramTheme.HologramViolet,
            Location = new Point(26, 152),
            Size = new Size(488, 22),
            BackColor = HologramTheme.PanelGlass
        };

        string? resultKey = null;

        var btnOk = new NeonButton
        {
            Text = "🔓 Aceptar y Descifrar",
            Variant = NeonButtonVariant.Success,
            AutoFitWidth = false,
            Location = new Point(26, 198),
            Size = new Size(236, 44)
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
            AutoFitWidth = false,
            Location = new Point(278, 198),
            Size = new Size(236, 44)
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

        var header = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            ColumnCount = 1,
            RowCount = 2,
            BackColor = HologramTheme.PanelGlass
        };
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
        header.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        header.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        var lblTitle = new Label
        {
            Text = $"Consultas de Registros ({NodeRuntimeState.CurrentNodeId} • v{NodeRuntimeState.ProtocolVersion})",
            Font = new Font("Segoe UI", 14f, FontStyle.Bold),
            ForeColor = HologramTheme.TextPrimary,
            Dock = DockStyle.Top,
            AutoSize = true,
            BackColor = HologramTheme.PanelGlass
        };

        var controlsFlow = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            WrapContents = true,
            FlowDirection = FlowDirection.LeftToRight,
            Padding = new Padding(0, 8, 0, 4),
            BackColor = HologramTheme.PanelGlass
        };

        _txtSearchHistory = HologramTheme.CreateDarkTextBox();
        _txtSearchHistory.PlaceholderText = "Buscar por archivo, algoritmo, nodo origen o PacketId...";
        _txtSearchHistory.Size = new Size(280, 30);
        _txtSearchHistory.Margin = new Padding(0, 5, 10, 4);
        _txtSearchHistory.TextChanged += (_, _) => RefreshConsultasGrid();

        _cmbFilterOrigin = new ComboBox
        {
            Size = new Size(140, 30),
            Margin = new Padding(0, 5, 14, 4),
            Font = new Font("Segoe UI", 9f, FontStyle.Bold)
        };
        HologramTheme.StyleComboBox(_cmbFilterOrigin);
        _cmbFilterOrigin.Items.AddRange(new object[] { "Todos", "Local", "Relay", "Recibido", "Resultado", "API-v2.0" });
        _cmbFilterOrigin.SelectedIndex = 0;
        _cmbFilterOrigin.SelectedIndexChanged += (_, _) => RefreshConsultasGrid();

        var btnLoad = new NeonButton { Text = "⚡ Cargar en Dashboard", Variant = NeonButtonVariant.Primary, Margin = new Padding(0, 2, 8, 2) };
        btnLoad.FitToText(minWidth: 175, height: 36);
        btnLoad.Click += (_, _) => LoadSelectedHistoryRecord();

        var btnCopyKeyRef = new NeonButton { Text = "🔗 Copiar Link", Variant = NeonButtonVariant.Secondary, Margin = new Padding(0, 2, 8, 2) };
        btnCopyKeyRef.FitToText(minWidth: 124, height: 36);
        btnCopyKeyRef.Click += (_, _) =>
        {
            var r = GetSelectedRegistro();
            if (r == null) return;
            string kr = string.IsNullOrWhiteSpace(r.LinkDescifradoRemoto) ? $"keyRef://{r.NodoRaiz}/{r.PacketId}" : r.LinkDescifradoRemoto;
            Clipboard.SetText(kr);
            MessageBox.Show(this, $"Referencia copiada:\n{kr}", "Portapapeles", MessageBoxButtons.OK, MessageBoxIcon.Information);
        };

        var btnDelete = new NeonButton { Text = "🗑 Eliminar", Variant = NeonButtonVariant.Danger, Margin = new Padding(0, 2, 8, 2) };
        btnDelete.FitToText(minWidth: 110, height: 36);
        btnDelete.Click += (_, _) =>
        {
            var r = GetSelectedRegistro();
            if (r == null) return;
            using var db = new AppDbContext();
            var entity = db.RegistrosCifrados.Find(r.Id);
            if (entity != null) { db.RegistrosCifrados.Remove(entity); db.SaveChanges(); }
            RefreshConsultasGrid();
        };

        controlsFlow.Controls.AddRange(new Control[] { _txtSearchHistory, _cmbFilterOrigin, btnLoad, btnCopyKeyRef, btnDelete });

        header.Controls.Add(lblTitle, 0, 0);
        header.Controls.Add(controlsFlow, 0, 1);

        _gridConsultas = new DataGridView { Dock = DockStyle.Fill };
        HologramTheme.StyleDataGrid(_gridConsultas);
        _gridConsultas.CellDoubleClick += (_, _) => LoadSelectedHistoryRecord();

        var gridWrap = new Panel { Dock = DockStyle.Fill, Padding = new Padding(0, 10, 0, 0), BackColor = HologramTheme.PanelGlass };
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
        var query = db.RegistrosCifrados.AsNoTracking().AsQueryable();

        if (origin != "Todos")
            query = query.Where(r => r.Origen == origin);

        var list = query
            .OrderByDescending(r => r.FechaOperacion)
            .ThenByDescending(r => r.Id)
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
                NodoOrigen = r.NodoRaiz,
                RutaSaltos = string.Join(" → ", V2PacketZipService.TryDeserializeHops(r.RutaSaltosJson)),
                r.Origen,
                Fecha = r.FechaOperacion.ToString("yyyy-MM-dd HH:mm:ss")
            })
            .ToList();

        _gridConsultas.DataSource = null;
        _gridConsultas.DataSource = list;
    }

    private RegistroCifrado? GetSelectedRegistro()
    {
        if (_gridConsultas.SelectedRows.Count == 0) return null;
        int id = Convert.ToInt32(_gridConsultas.SelectedRows[0].Cells["Id"].Value);
        using var db = new AppDbContext();
        return db.RegistrosCifrados.AsNoTracking().FirstOrDefault(r => r.Id == id);
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
        _isShowingEncrypted = !string.Equals(r.Origen, "Resultado", StringComparison.OrdinalIgnoreCase);
        _binarySummaryReport = null;
        _lastSavedDecryptedPath = null;

        _relayProducerNode = r.NodoRaiz;
        _relayHopHistory = V2PacketZipService.TryDeserializeHops(r.RutaSaltosJson);

        SelectAlgorithmInCombo(r.AlgoritmoCodigo);
        UpdateMetadataPanel(r, !string.IsNullOrWhiteSpace(r.FirmaRaizBase64), !string.IsNullOrWhiteSpace(r.FirmaRaizBase64));

        if (_isShowingEncrypted)
            _hologram.TriggerEncryptAnimation(r.AlgoritmoCodigo);
        else
            _hologram.TriggerDecryptAnimation(r.AlgoritmoCodigo);

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

        // Recuadro de IP Activa ubicado exclusivamente dentro de Red de Nodos
        var networkViewIpCard = CreateNetworkViewIpCardControl();

        var header = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            ColumnCount = 1,
            RowCount = 2,
            Padding = new Padding(0, 6, 0, 0),
            BackColor = HologramTheme.PanelGlass
        };
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
        header.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        header.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        var titleStack = new Panel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            BackColor = HologramTheme.PanelGlass
        };
        string netTitle = NodeRuntimeState.IsV2
            ? "Directorio de Nodos v2.0 (UDP 5099 • Escaneo 5001–5020 • TOFU)"
            : "Directorio de Nodos v1.0 (Escaneo LAN :5000 • Localhost 5000–5008)";

        string netSub = NodeRuntimeState.IsV2
            ? "Beacons CC-BEACON cada 30s, escaneo HTTP de respaldo, fijado TOFU y diagnóstico de conectividad de 3 capas"
            : "Interoperabilidad dual ModuloCrypto v1.0 / CentroCiberseguridad v1 y diagnóstico de conectividad de 3 capas";

        var lblTitle = new Label
        {
            Text = netTitle,
            Font = new Font("Segoe UI", 14f, FontStyle.Bold),
            ForeColor = HologramTheme.TextPrimary,
            Dock = DockStyle.Top,
            AutoSize = true,
            BackColor = HologramTheme.PanelGlass
        };
        var lblSub = new Label
        {
            Text = netSub,
            Font = HologramTheme.FontBody(8.8f),
            ForeColor = HologramTheme.TextSecondary,
            Dock = DockStyle.Top,
            AutoSize = true,
            Padding = new Padding(0, 2, 0, 2),
            BackColor = HologramTheme.PanelGlass
        };
        titleStack.Controls.Add(lblSub);
        titleStack.Controls.Add(lblTitle);

        var netBtnFlow = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            WrapContents = true,
            FlowDirection = FlowDirection.LeftToRight,
            Padding = new Padding(0, 8, 0, 4),
            BackColor = HologramTheme.PanelGlass
        };

        var btnTestConn = new NeonButton
        {
            Text = "🧪 Probar Conexión (Ping + HTTP)",
            Variant = NeonButtonVariant.Primary,
            Margin = new Padding(0, 2, 8, 2)
        };
        btnTestConn.FitToText(minWidth: 235, height: 38);
        btnTestConn.Click += async (_, _) =>
        {
            btnTestConn.Enabled = false;
            btnTestConn.Text = "Diagnosticando...";
            btnTestConn.FitToText(minWidth: 235, height: 38);
            try
            {
                await HandleRunConnectivityDiagnosticAsync();
            }
            finally
            {
                if (!btnTestConn.IsDisposed)
                {
                    btnTestConn.Text = "🧪 Probar Conexión (Ping + HTTP)";
                    btnTestConn.FitToText(minWidth: 235, height: 38);
                    btnTestConn.Enabled = true;
                }
            }
        };

        var btnPingAll = new NeonButton
        {
            Text = "📡 Ping 8 Nodos",
            Variant = NeonButtonVariant.Cyan,
            Margin = new Padding(0, 2, 8, 2)
        };
        btnPingAll.FitToText(minWidth: 145, height: 38);
        btnPingAll.Click += async (_, _) =>
        {
            btnPingAll.Enabled = false;
            btnPingAll.Text = "Verificando...";
            try
            {
                foreach (var peer in NodeRuntimeState.NetworkPeers)
                {
                    if (NodeRuntimeState.IsV2)
                        await V2NetworkClient.PingNodeAsync(peer, customTimeoutMs: 600);
                    else
                        await V1NetworkClient.PingNodeAsync(peer, customTimeoutMs: 700);
                }
                RefreshNetworkGrid();
            }
            finally
            {
                if (!btnPingAll.IsDisposed)
                {
                    btnPingAll.Text = "📡 Ping 8 Nodos";
                    btnPingAll.FitToText(minWidth: 145, height: 38);
                    btnPingAll.Enabled = true;
                }
            }
        };

        var btnConfirmTofu = new NeonButton
        {
            Text = "🛡 Confirmar Huella TOFU",
            Variant = NeonButtonVariant.Success,
            Margin = new Padding(0, 2, 8, 2),
            Visible = NodeRuntimeState.IsV2
        };
        btnConfirmTofu.FitToText(minWidth: 180, height: 38);
        btnConfirmTofu.Click += (_, _) => HandleConfirmSelectedPeerTofu();

        var btnScanLocalhost = new NeonButton
        {
            Text = "💻 Escanear Localhost",
            Variant = NeonButtonVariant.Secondary,
            Margin = new Padding(0, 2, 8, 2)
        };
        btnScanLocalhost.FitToText(minWidth: 170, height: 38);
        btnScanLocalhost.Click += async (_, _) =>
        {
            btnScanLocalhost.Enabled = false;
            btnScanLocalhost.Text = "Escaneando 127.0.0.1...";
            try
            {
                List<PeerNode> found = NodeRuntimeState.IsV2
                    ? await V2NetworkClient.ScanLocalhostPortsAsync(5001, 5020)
                    : await V1NetworkClient.ScanLocalhostPortsAsync(5000, 5008);

                int integrated = IntegrateDiscoveredPeers(found);
                RefreshNetworkGrid();
                RefreshTargetPeerCombo();

                MessageBox.Show(this,
                    $"Escaneo de Localhost (v{NodeRuntimeState.ProtocolVersion}) completado.\n" +
                    $"• Nodos detectados: {found.Count}\n" +
                    $"• Nodos actualizados en directorio: {integrated}",
                    $"Descubrimiento Localhost v{NodeRuntimeState.ProtocolVersion}", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            finally
            {
                if (!btnScanLocalhost.IsDisposed)
                {
                    btnScanLocalhost.Text = "💻 Escanear Localhost";
                    btnScanLocalhost.FitToText(minWidth: 170, height: 38);
                    btnScanLocalhost.Enabled = true;
                }
            }
        };

        var btnScanLan = new NeonButton
        {
            Text = "🔍 Auto-Descubrir LAN",
            Variant = NeonButtonVariant.Secondary,
            Margin = new Padding(0, 2, 8, 2)
        };
        btnScanLan.FitToText(minWidth: 175, height: 38);
        btnScanLan.Click += async (_, _) =>
        {
            btnScanLan.Enabled = false;
            btnScanLan.Text = "Escaneando /24...";
            try
            {
                List<PeerNode> found;
                if (NodeRuntimeState.IsV2)
                {
                    var (f, _) = await V2NetworkClient.ScanLanSubnetAsync(NodeRuntimeState.LocalIpAddress, 5001, 5020, isAutomaticTrigger: false);
                    found = f;
                }
                else
                {
                    found = await V1NetworkClient.ScanLanSubnetAsync(NodeRuntimeState.LocalIpAddress, 5000);
                }

                int integrated = IntegrateDiscoveredPeers(found);
                RefreshNetworkGrid();
                RefreshTargetPeerCombo();

                MessageBox.Show(this,
                    $"Escaneo HTTP en subred /24 de {NodeRuntimeState.LocalIpAddress} completado.\n" +
                    $"• Nodos v{NodeRuntimeState.ProtocolVersion} detectados: {found.Count}\n" +
                    $"• Nodos integrados en directorio: {integrated}",
                    $"Escaneo Subred LAN v{NodeRuntimeState.ProtocolVersion}", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            finally
            {
                if (!btnScanLan.IsDisposed)
                {
                    btnScanLan.Text = "🔍 Auto-Descubrir LAN";
                    btnScanLan.FitToText(minWidth: 175, height: 38);
                    btnScanLan.Enabled = true;
                }
            }
        };

        netBtnFlow.Controls.AddRange(new Control[] { btnTestConn, btnPingAll, btnConfirmTofu, btnScanLocalhost, btnScanLan });

        header.Controls.Add(titleStack, 0, 0);
        header.Controls.Add(netBtnFlow, 0, 1);

        var editBar = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            AutoSize = true,
            WrapContents = true,
            FlowDirection = FlowDirection.LeftToRight,
            Padding = new Padding(0, 10, 0, 4),
            BackColor = HologramTheme.PanelGlass
        };

        var lblIp = new Label
        {
            Text = "IP del Nodo Seleccionado:",
            ForeColor = HologramTheme.TextSecondary,
            AutoSize = true,
            Margin = new Padding(0, 9, 8, 4),
            Font = HologramTheme.FontBody(9.2f),
            BackColor = HologramTheme.PanelGlass
        };
        _txtEditPeerIp = HologramTheme.CreateDarkTextBox();
        _txtEditPeerIp.Size = new Size(180, 28);
        _txtEditPeerIp.Margin = new Padding(0, 5, 14, 4);

        var lblPort = new Label
        {
            Text = "Puerto:",
            ForeColor = HologramTheme.TextSecondary,
            AutoSize = true,
            Margin = new Padding(0, 9, 8, 4),
            Font = HologramTheme.FontBody(9.2f),
            BackColor = HologramTheme.PanelGlass
        };
        _txtEditPeerPort = HologramTheme.CreateDarkTextBox();
        _txtEditPeerPort.Size = new Size(80, 28);
        _txtEditPeerPort.Margin = new Padding(0, 5, 14, 4);
        _txtEditPeerPort.Text = NodeRuntimeState.ApiPort.ToString();

        var btnSavePeer = new NeonButton
        {
            Text = "💾 Guardar IP",
            Variant = NeonButtonVariant.Primary,
            Margin = new Padding(0, 2, 8, 2)
        };
        btnSavePeer.FitToText(minWidth: 150, height: 36);
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

            btnSavePeer.Enabled = false;
            try
            {
                if (NodeRuntimeState.IsV2)
                {
                    await V2NetworkClient.PingNodeAsync(peer, customTimeoutMs: 900);
                    AppDbContext.UpsertTrustedPeer(peer);
                }
                else
                {
                    await V1NetworkClient.PingNodeAsync(peer, customTimeoutMs: 900);
                }
                RefreshNetworkGrid();
                RefreshTargetPeerCombo();
            }
            finally
            {
                if (!btnSavePeer.IsDisposed) btnSavePeer.Enabled = true;
            }
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
                e.CellStyle!.ForeColor = s.Contains("BLOQUEADO") || s.Contains("CAMBIADA") ? HologramTheme.Danger :
                                         s.Contains("Online") ? HologramTheme.Success : HologramTheme.TextSecondary;
            }
            else if (colName == "ConfianzaTOFU" && e.Value is string tofu)
            {
                e.CellStyle!.ForeColor = tofu.Contains("CAMBIADA") ? HologramTheme.Danger :
                                         tofu.Contains("Fijada") || tofu.Contains("Activa") ? HologramTheme.Success : HologramTheme.Warning;
            }
        };

        var gridWrap = new Panel { Dock = DockStyle.Fill, Padding = new Padding(0, 10, 0, 0), BackColor = HologramTheme.PanelGlass };
        gridWrap.Controls.Add(_gridPeers);

        card.Controls.Add(gridWrap);
        card.Controls.Add(editBar);
        card.Controls.Add(header);
        card.Controls.Add(networkViewIpCard);
        panel.Controls.Add(card);
    }

    private async Task HandleRunConnectivityDiagnosticAsync()
    {
        string targetIp = _txtEditPeerIp.Text.Trim();
        int targetPort = int.TryParse(_txtEditPeerPort.Text.Trim(), out int p) && p > 0 && p < 65536
            ? p
            : NodeRuntimeState.ApiPort;

        PeerNode? selectedPeer = null;
        if (_gridPeers.SelectedRows.Count > 0)
        {
            string nodeId = _gridPeers.SelectedRows[0].Cells["NodeId"].Value?.ToString() ?? "";
            selectedPeer = NodeRuntimeState.NetworkPeers.FirstOrDefault(x => x.NodeId == nodeId);
            if (string.IsNullOrWhiteSpace(targetIp) && selectedPeer != null)
            {
                targetIp = selectedPeer.IpAddress;
                targetPort = selectedPeer.Port;
            }
        }

        if (string.IsNullOrWhiteSpace(targetIp))
            targetIp = "127.0.0.1";

        var report = await ConnectivityDiagnostics.RunFullDiagnosticAsync(
            targetIp,
            targetPort,
            NodeRuntimeState.ActiveProtocolVersion);

        if (selectedPeer != null)
        {
            selectedPeer.IpAddress = targetIp;
            selectedPeer.Port = targetPort;
            if (report.HttpApiSuccess && !report.HasVersionMismatch)
            {
                if (NodeRuntimeState.IsV2)
                    await V2NetworkClient.PingNodeAsync(selectedPeer, customTimeoutMs: 1200);
                else
                    await V1NetworkClient.PingNodeAsync(selectedPeer, customTimeoutMs: 1200);
            }
            else
            {
                selectedPeer.Status = "offline";
                selectedPeer.LastLatency = report.TcpPortOpen ? $"{report.TcpConnectMs} ms (TCP)" : "Inalcanzable";
            }
            RefreshNetworkGrid();
        }

        var icon = report.HasVersionMismatch || (!report.TcpPortOpen && report.IcmpPingSuccess)
            ? MessageBoxIcon.Warning
            : (report.HttpApiSuccess ? MessageBoxIcon.Information : MessageBoxIcon.Error);

        MessageBox.Show(
            this,
            report.FullFormattedReport,
            $"Diagnóstico de Conectividad — {report.SummaryTitle}",
            MessageBoxButtons.OK,
            icon);
    }

    private void HandleConfirmSelectedPeerTofu()
    {
        if (!NodeRuntimeState.IsV2) return;
        if (_gridPeers.SelectedRows.Count == 0) return;
        string nodeId = _gridPeers.SelectedRows[0].Cells["NodeId"].Value?.ToString() ?? "";
        var peer = NodeRuntimeState.NetworkPeers.FirstOrDefault(p => p.NodeId == nodeId);
        if (peer == null) return;

        if (string.IsNullOrWhiteSpace(peer.CertThumbprint))
        {
            MessageBox.Show(this,
                $"El nodo {peer.NodeId} aún no ha anunciado un certificado X.509.\nEjecuta primero [🧪 Probar Conexión] o [📡 Ping 8 Nodos].",
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
            V2NetworkClient.ConfirmPeerTofu(peer);
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
                if (NodeRuntimeState.IsV2)
                    AppDbContext.UpsertTrustedPeer(existing);
                count++;
            }
            else
            {
                NodeRuntimeState.NetworkPeers.Add(d);
                if (NodeRuntimeState.IsV2)
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
            Protocolo = p.ProtocolType,
            Origen = p.Source,
            Endpoint = p.BaseUrl,
            Estado = p.HasThumbprintMismatch ? "⛔ HUELLA CAMBIADA" : (p.IsOnline ? "● Online" : "● Offline"),
            ConfianzaTOFU = NodeRuntimeState.IsV2
                ? (p.HasThumbprintMismatch ? "⛔ HUELLA CAMBIADA" : (p.IsConfirmed ? "✓ Fijada (TOFU)" : "⚠ Pendiente Confirmar"))
                : "✓ X.509 Dual Activa",
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
            Text = $"Identidad {NodeRuntimeState.CurrentNodeId} & Certificado X.509 v{NodeRuntimeState.ProtocolVersion} (DPAPI)",
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
            Text = "🔄 Regenerar Certificado X.509 RSA-2048",
            Variant = NeonButtonVariant.Primary,
            Dock = DockStyle.Bottom,
            Height = 44
        };
        btnRegen.Click += async (_, _) =>
        {
            var newCert = _runtime.RegenerateCertificate();
            RefreshSettingsStats();
            await _runtime.AnnouncePresenceAsync();
            MessageBox.Show(this,
                $"Nuevo certificado X.509 RSA-2048 generado para v{NodeRuntimeState.ProtocolVersion}:\n{newCert.Subject}",
                $"Certificado X.509 v{NodeRuntimeState.ProtocolVersion} — {NodeRuntimeState.CurrentNodeId}",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        };

        var certSpacer = new Panel { Dock = DockStyle.Bottom, Height = 12, BackColor = HologramTheme.PanelGlass };
        leftCard.Controls.Add(_txtSettingsCertInfo);
        leftCard.Controls.Add(certSpacer);
        leftCard.Controls.Add(btnRegen);
        leftCard.Controls.Add(lblCertTitle);

        var rightCard = new GlassPanel { Dock = DockStyle.Fill, CornerRadius = 18, Padding = new Padding(20), Margin = new Padding(10, 0, 0, 0) };
        var lblDbTitle = new Label
        {
            Text = "SQLite (Modo WAL / TOFU / Anti-Replay) & Holograma",
            Font = new Font("Segoe UI", 13.5f, FontStyle.Bold),
            ForeColor = HologramTheme.HologramViolet,
            Dock = DockStyle.Top,
            Height = 36,
            BackColor = HologramTheme.PanelGlass
        };

        _lblSettingsDbStats = new Label
        {
            Dock = DockStyle.Top,
            Height = 200,
            Font = HologramTheme.FontMono(9f),
            ForeColor = HologramTheme.TextPrimary,
            Padding = new Padding(0, 8, 0, 8),
            BackColor = HologramTheme.PanelGlass
        };

        var lblHoloTest = new Label
        {
            Text = "PRUEBA RÁPIDA DE ESTADOS DEL HOLOGRAMA 3D:",
            Dock = DockStyle.Top,
            Height = 30,
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            ForeColor = HologramTheme.HologramCyan,
            BackColor = HologramTheme.PanelGlass
        };

        var testFlow = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            AutoScroll = true,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            Padding = new Padding(0, 6, 0, 6),
            BackColor = HologramTheme.PanelGlass
        };

        var btnTestIdle = new NeonButton { Text = "1. Estado Reposo (Cubo Azul)", Variant = NeonButtonVariant.Cyan, Margin = new Padding(0, 0, 0, 8) };
        btnTestIdle.FitToText(minWidth: 340, height: 40);
        btnTestIdle.Click += (_, _) => { _hologram.SetIdle(string.Empty); SwitchView("dashboard"); };

        var btnTestLock = new NeonButton { Text = "2. Estado Cifrar (Candado Cerrado Rojo)", Variant = NeonButtonVariant.Danger, Margin = new Padding(0, 0, 0, 8) };
        btnTestLock.FitToText(minWidth: 340, height: 40);
        btnTestLock.Click += (_, _) => { _hologram.TriggerEncryptAnimation("AESGCM"); SwitchView("dashboard"); };

        var btnTestUnlock = new NeonButton { Text = "3. Estado Descifrar (Candado Abierto Verde)", Variant = NeonButtonVariant.Success, Margin = new Padding(0, 0, 0, 8) };
        btnTestUnlock.FitToText(minWidth: 340, height: 40);
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

        NodeRuntimeState.SqliteConnected = AppDbContext.TestConnection(out string diag);
        NodeRuntimeState.SqliteDiagnostic = diag;
        UpdateSqlitePillState();

        _txtSettingsCertInfo.Text = _runtime.GetCertificateDetailsReport(_userFullName, _currentUser.NombreUsuario);

        using var db = new AppDbContext();
        int uCount = db.Usuarios.Count();
        int rCount = db.RegistrosCifrados.Count();
        int sCount = db.SolicitudesEntrantes.Count();
        int sPend = db.SolicitudesEntrantes.Count(s => s.Estado == "Pendiente");
        int tCount = db.TrustedPeers.Count();
        int spCount = db.SeenPackets.Count();
        int kCount = db.AsymmetricKeys.Count();

        _lblSettingsDbStats.Text =
            $"Estado SQLite      : {(NodeRuntimeState.SqliteConnected ? "ONLINE (WAL Activo)" : "ERROR")}\r\n" +
            $"Diagnóstico        : {NodeRuntimeState.SqliteDiagnostic}\r\n" +
            $"Tabla Usuarios     : {uCount} integrante(s) (PBKDF2-SHA256)\r\n" +
            $"Tabla Consultas    : {rCount} registro(s) local(es)\r\n" +
            $"Tabla Solicitudes  : {sCount} total ({sPend} pendiente(s))\r\n" +
            $"Tabla TrustedPeers : {tCount} nodo(s) en directorio TOFU\r\n" +
            $"Tabla SeenPackets  : {spCount} paquete(s) Anti-Replay\r\n" +
            $"Tabla AsymmetricKey: {kCount} par(es) de llave (DPAPI)";
    }
}
