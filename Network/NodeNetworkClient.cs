using ModuloCrypto.Core.Contracts;
using ModuloCrypto.Core.Data;
using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text.Json;

namespace ModuloCrypto.Network;

/// <summary>
/// Cliente HTTP v2.0 para comunicación entre nodos (EQ01–EQ08), escaneo de subred /24 en puertos 5001–5020
/// (timeout 500 ms, máx. 64 conexiones paralelas, cooldown automático de 5 minutos) y validación TOFU.
/// </summary>
public static class NodeNetworkClient
{
    private static readonly HttpClient Http = new()
    {
        Timeout = TimeSpan.FromSeconds(12)
    };

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private static DateTime _lastAutoSubnetScanUtc = DateTime.MinValue;
    public static readonly TimeSpan AutoScanCooldown = TimeSpan.FromMinutes(5);

    public static async Task<(bool Online, string Latency, PeerStatusResponse? Info)> PingNodeAsync(
        PeerNode node,
        int? customTimeoutMs = null)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            using var cts = new CancellationTokenSource(customTimeoutMs ?? 1500);
            var resp = await Http.GetAsync($"{node.BaseUrl}/api/status", cts.Token);
            sw.Stop();

            if (!resp.IsSuccessStatusCode)
                return (false, "HTTP " + (int)resp.StatusCode, null);

            string body = await resp.Content.ReadAsStringAsync(cts.Token);
            var status = JsonSerializer.Deserialize<PeerStatusResponse>(body, JsonOpts);
            if (status == null || !string.Equals(status.ProtocolVersion, "2.0", StringComparison.Ordinal))
                return (false, "Protocolo != 2.0", null);

            node.ProtocolType = "v2.0";
            node.LastSeenUtc = DateTime.UtcNow;
            node.LastLatency = $"{sw.ElapsedMilliseconds} ms";

            if (NodeRuntimeState.IsValidNodeId(status.NodeId))
                node.NodeId = status.NodeId.ToUpperInvariant();
            if (status.TeamNumber > 0)
                node.TeamNumber = status.TeamNumber;
            if (status.Algorithms is { Count: > 0 })
            {
                node.AlgorithmsJson = JsonSerializer.Serialize(status.Algorithms);
                node.RoleLabel = $"Equipo {node.TeamNumber:D2} ({string.Join(", ", status.Algorithms)})";
            }

            ApplyTofuThumbprintCheck(node, status.CertificateThumbprintSha256);

            if (!node.HasThumbprintMismatch)
                await FetchAndValidatePeerCertificateAsync(node, customTimeoutMs ?? 1500);

            AppDbContext.UpsertTrustedPeer(node);
            return (true, node.LastLatency, status);
        }
        catch
        {
            sw.Stop();
            return (false, "Timeout", null);
        }
    }

    public static void ApplyTofuThumbprintCheck(PeerNode peer, string? advertisedThumbprint)
    {
        string cleanThumb = (advertisedThumbprint ?? "").Trim().ToUpperInvariant();
        if (string.IsNullOrWhiteSpace(cleanThumb)) return;

        peer.CertThumbprint = cleanThumb;

        // Si el nodo ya tenía una huella fijada (IsConfirmed) y la huella nueva es diferente -> BLOQUEAR INMEDIATAMENTE
        if (peer.IsConfirmed &&
            !string.IsNullOrWhiteSpace(peer.PinnedThumbprintSha256) &&
            !NodeCertificateService.FixedTimeEqualsHex(peer.PinnedThumbprintSha256, cleanThumb))
        {
            peer.HasThumbprintMismatch = true;
            peer.Status = "blocked";
        }
        else
        {
            peer.HasThumbprintMismatch = false;
            peer.Status = "online";
        }
    }

    public static async Task<bool> FetchAndValidatePeerCertificateAsync(PeerNode peer, int timeoutMs = 1500)
    {
        try
        {
            using var cts = new CancellationTokenSource(timeoutMs);
            var resp = await Http.GetAsync($"{peer.BaseUrl}/api/certificate", cts.Token);
            if (!resp.IsSuccessStatusCode) return false;

            string body = await resp.Content.ReadAsStringAsync(cts.Token);
            string pem;
            if (body.TrimStart().StartsWith("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
            {
                pem = body.Trim();
            }
            else
            {
                var dto = JsonSerializer.Deserialize<PeerCertificateResponse>(body, JsonOpts);
                pem = dto?.CertificatePem ?? string.Empty;
            }

            if (string.IsNullOrWhiteSpace(pem)) return false;

            using var cert = NodeCertificateService.LoadCertificateFromPemOrBase64(pem);
            if (!NodeCertificateService.ValidateCertificateMetadata(cert, peer.NodeId, peer.CertThumbprint, out _))
            {
                peer.HasThumbprintMismatch = true;
                peer.Status = "blocked";
                return false;
            }

            string actualThumb = NodeCertificateService.GetThumbprintSha256Hex(cert);
            peer.CertificatePem = pem;
            ApplyTofuThumbprintCheck(peer, actualThumb);
            return !peer.HasThumbprintMismatch;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Fija (TOFU) o re-confirma explícitamente la huella X.509 de un nodo en SQLite.
    /// </summary>
    public static void ConfirmPeerTofu(PeerNode peer)
    {
        if (string.IsNullOrWhiteSpace(peer.CertThumbprint)) return;
        peer.PinnedThumbprintSha256 = peer.CertThumbprint.ToUpperInvariant();
        peer.IsConfirmed = true;
        peer.HasThumbprintMismatch = false;
        peer.Status = "online";
        AppDbContext.UpsertTrustedPeer(peer);
        NodeRuntimeState.NotifyPeerChanged(peer);
    }

    public static async Task<(bool Success, string Message)> SendZipPacketAsync(
        PeerNode targetPeer,
        string zipPath,
        string packetId,
        string packetType = "package")
    {
        if (targetPeer.HasThumbprintMismatch || string.Equals(targetPeer.Status, "blocked", StringComparison.OrdinalIgnoreCase))
        {
            return (false, $"BLOQUEO TOFU (E-CERT-UNTRUSTED): El nodo {targetPeer.NodeId} presentó un cambio de huella X.509. Debes reconfirmar su huella en 'Red de Nodos (IP)' antes de enviar paquetes.");
        }

        byte[] fileBytes = await File.ReadAllBytesAsync(zipPath);
        if (fileBytes.Length > PacketZipService.MaxCompressedZipBytes)
        {
            return (false, "E-SIZE: El paquete .zip supera el límite máximo de 50 MB.");
        }

        string fileName = Path.GetFileName(zipPath);
        string endpointPath = string.Equals(packetType, "result", StringComparison.OrdinalIgnoreCase)
            ? "/api/results/receive"
            : "/api/requests/receive";

        string url = targetPeer.BaseUrl.TrimEnd('/') + endpointPath;

        try
        {
            using var form = new MultipartFormDataContent();
            var content = new ByteArrayContent(fileBytes);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/zip");
            form.Add(content, "package", fileName);

            using var req = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = form
            };
            req.Headers.TryAddWithoutValidation("X-Source-Node", NodeRuntimeState.CurrentNodeId);
            req.Headers.TryAddWithoutValidation("X-Packet-Id", packetId);
            req.Headers.TryAddWithoutValidation("X-Protocol-Version", "2.0");

            var resp = await Http.SendAsync(req);
            string body = await resp.Content.ReadAsStringAsync();

            if (resp.IsSuccessStatusCode)
            {
                targetPeer.Status = "online";
                targetPeer.LastSeenUtc = DateTime.UtcNow;
                return (true, $"Paquete v2.0 entregado a {url}.\nHTTP {(int)resp.StatusCode}: {body}");
            }

            return (false, $"Rechazado por {targetPeer.NodeId} (HTTP {(int)resp.StatusCode}):\n{body}");
        }
        catch (Exception ex)
        {
            return (false, $"Error de conexión hacia {url}: {ex.Message}");
        }
    }

    public static async Task<List<PeerNode>> ScanLocalhostPortsAsync(int startPort = 5001, int endPort = 5020)
    {
        var found = new ConcurrentBag<PeerNode>();
        var ports = Enumerable.Range(startPort, Math.Max(1, endPort - startPort + 1));

        await Parallel.ForEachAsync(ports, async (port, _) =>
        {
            var probe = new PeerNode
            {
                NodeId = $"EQ{(port - 5000):D2}",
                TeamNumber = Math.Clamp(port - 5000, 1, 99),
                IpAddress = "127.0.0.1",
                Port = port,
                Source = "scan",
                ProtocolType = "v2.0"
            };

            var (online, _, _) = await PingNodeAsync(probe, customTimeoutMs: 500);
            if (online)
            {
                found.Add(probe);
            }
        });

        return found.OrderBy(p => p.Port).ToList();
    }

    /// <summary>
    /// Escaneo HTTP de respaldo en subred /24 sobre puertos 5001–5020 (timeout 500 ms, máx. 64 conexiones paralelas,
    /// cooldown de 5 minutos para ejecuciones automáticas).
    /// </summary>
    public static async Task<(List<PeerNode> Found, bool SkippedByCooldown)> ScanLanSubnetAsync(
        string localIp,
        int startPort = 5001,
        int endPort = 5020,
        bool isAutomaticTrigger = false)
    {
        if (isAutomaticTrigger && (DateTime.UtcNow - _lastAutoSubnetScanUtc) < AutoScanCooldown)
        {
            return (new List<PeerNode>(), true);
        }

        _lastAutoSubnetScanUtc = DateTime.UtcNow;
        var found = new ConcurrentBag<PeerNode>();

        string prefix = "192.168.1.";
        var parts = (localIp ?? "").Split('.');
        if (parts.Length == 4 && parts[0] != "127")
            prefix = $"{parts[0]}.{parts[1]}.{parts[2]}.";

        // En escaneo manual de red LAN priorizamos el rango oficial de equipos (5001..5008 o startPort..endPort) con 64 conexiones en paralelo y 500ms timeout
        var targets = new List<(string Ip, int Port)>();
        for (int host = 1; host <= 254; host++)
        {
            string ip = $"{prefix}{host}";
            for (int port = startPort; port <= endPort; port++)
                targets.Add((ip, port));
        }

        using var sem = new SemaphoreSlim(64);
        var tasks = targets.Select(async target =>
        {
            await sem.WaitAsync();
            try
            {
                var probe = new PeerNode
                {
                    NodeId = $"EQ{Math.Clamp(target.Port - 5000, 1, 99):D2}",
                    TeamNumber = Math.Clamp(target.Port - 5000, 1, 99),
                    IpAddress = target.Ip,
                    Port = target.Port,
                    Source = "scan",
                    ProtocolType = "v2.0"
                };

                var (online, _, _) = await PingNodeAsync(probe, customTimeoutMs: 500);
                if (online)
                {
                    found.Add(probe);
                }
            }
            finally
            {
                sem.Release();
            }
        });

        await Task.WhenAll(tasks);
        return (found.OrderBy(p => p.IpAddress).ThenBy(p => p.Port).ToList(), false);
    }
}
