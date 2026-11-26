using ModuloCrypto.Core.Contracts;
using ModuloCrypto.Core.Data;
using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace ModuloCrypto.Network.V2;

/// <summary>
/// Cliente HTTP v2.0 con SocketsHttpHandler optimizado, cabeceras X-CC-Node / X-CC-Protocol: 2.0 / X-CC-Request-Id,
/// delegación criptográfica remota (/api/crypto/forward e inverse con CC-ENV-1), escaneo de subred /24 en puertos 5001–5020
/// (SemaphoreSlim(64, 64), timeout 500 ms, cooldown 5 min) y validación TOFU.
/// </summary>
public static class V2NetworkClient
{
    private static readonly HttpClient Http = new(new SocketsHttpHandler
    {
        PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        ConnectTimeout = TimeSpan.FromSeconds(3)
    })
    {
        Timeout = TimeSpan.FromSeconds(35)
    };

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private static DateTime _lastAutoSubnetScanUtc = DateTime.MinValue;
    public static readonly TimeSpan AutoScanCooldown = TimeSpan.FromMinutes(5);

    private static void AddStandardV2Headers(HttpRequestMessage req, string? requestId = null)
    {
        string reqId = string.IsNullOrWhiteSpace(requestId)
            ? Guid.NewGuid().ToString("D").ToLowerInvariant()
            : requestId;

        req.Headers.TryAddWithoutValidation("X-CC-Node", NodeRuntimeState.CurrentNodeId);
        req.Headers.TryAddWithoutValidation("X-CC-Protocol", "2.0");
        req.Headers.TryAddWithoutValidation("X-CC-Request-Id", reqId);
    }

    public static async Task<(bool Online, string Latency, PeerStatusResponse? Info)> PingNodeAsync(
        PeerNode node,
        int? customTimeoutMs = null)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            using var cts = new CancellationTokenSource(customTimeoutMs ?? 1500);
            using var req = new HttpRequestMessage(HttpMethod.Get, $"{node.BaseUrl}/api/status");
            AddStandardV2Headers(req);

            var resp = await Http.SendAsync(req, cts.Token);
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

        if (peer.IsConfirmed &&
            !string.IsNullOrWhiteSpace(peer.PinnedThumbprintSha256) &&
            !V2CertificateService.FixedTimeEqualsHex(peer.PinnedThumbprintSha256, cleanThumb))
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
            using var req = new HttpRequestMessage(HttpMethod.Get, $"{peer.BaseUrl}/api/certificate");
            AddStandardV2Headers(req);

            var resp = await Http.SendAsync(req, cts.Token);
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

            using var cert = V2CertificateService.LoadCertificateFromPemOrBase64(pem);
            if (!V2CertificateService.ValidateCertificateMetadata(cert, peer.NodeId, out _))
            {
                peer.HasThumbprintMismatch = true;
                peer.Status = "blocked";
                return false;
            }

            string actualThumb = V2CertificateService.GetThumbprintSha256Hex(cert);
            if (!string.IsNullOrWhiteSpace(peer.CertThumbprint) &&
                !V2CertificateService.FixedTimeEqualsHex(actualThumb, peer.CertThumbprint))
            {
                peer.HasThumbprintMismatch = true;
                peer.Status = "blocked";
                return false;
            }

            peer.CertificatePem = pem;
            ApplyTofuThumbprintCheck(peer, actualThumb);
            return !peer.HasThumbprintMismatch;
        }
        catch
        {
            return false;
        }
    }

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
            return (false, $"BLOQUEO TOFU (E-CERT-UNTRUSTED): El nodo {targetPeer.NodeId} presentó un cambio de huella X.509. Reconfirma su huella en 'Red de Nodos (IP)' antes de enviar paquetes.");
        }

        byte[] fileBytes = await File.ReadAllBytesAsync(zipPath);
        if (fileBytes.Length > V2PacketZipService.MaxCompressedZipBytes)
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
            AddStandardV2Headers(req, packetId);

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

    /// <summary>
    /// Invoca POST /api/crypto/forward en un nodo proveedor v2.0 (firmando los bytes crudos de 'request' con RSA-PSS-SHA256).
    /// </summary>
    public static async Task<(bool Success, V2CryptoForwardResponse? Response, string ErrorMessage)> CallRemoteForwardAsync(
        PeerNode providerPeer,
        string algorithmCode,
        byte[] payloadBytes,
        string fileName,
        string extension,
        int keySizeBits = 256)
    {
        if (providerPeer.HasThumbprintMismatch)
            return (false, null, $"El nodo {providerPeer.NodeId} está bloqueado por cambio de huella TOFU.");

        string requestId = Guid.NewGuid().ToString("D").ToLowerInvariant();
        string packetId = Guid.NewGuid().ToString("D").ToLowerInvariant();

        var fwdReq = new V2CryptoForwardRequest
        {
            RequestId = requestId,
            PacketId = packetId,
            RequesterNode = NodeRuntimeState.CurrentNodeId,
            AlgorithmCode = algorithmCode.Trim().ToUpperInvariant(),
            Operation = "forward",
            OriginalFileName = fileName,
            OriginalExtension = extension,
            KeySizeBits = keySizeBits,
            TimestampUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        };

        byte[] rawRequestBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(fwdReq));
        string requestSigBase64 = V2CertificateService.SignDataPss(rawRequestBytes);
        string requesterCertPem = V2CertificateService.ExportPublicCertPem();

        using var form = new MultipartFormDataContent();
        var reqContent = new ByteArrayContent(rawRequestBytes);
        reqContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        form.Add(reqContent, "request", "request.json");
        form.Add(new StringContent(requestSigBase64, Encoding.UTF8), "requestSignature");
        form.Add(new StringContent(requesterCertPem, Encoding.UTF8), "requesterCertificate");

        var payloadContent = new ByteArrayContent(payloadBytes);
        payloadContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        form.Add(payloadContent, "payload", string.IsNullOrWhiteSpace(fileName) ? "payload.bin" : fileName);

        string url = $"{providerPeer.BaseUrl.TrimEnd('/')}/api/crypto/forward";
        using var httpReq = new HttpRequestMessage(HttpMethod.Post, url) { Content = form };
        AddStandardV2Headers(httpReq, requestId);

        var resp = await Http.SendAsync(httpReq);
        string body = await resp.Content.ReadAsStringAsync();

        if (!resp.IsSuccessStatusCode)
            return (false, null, $"HTTP {(int)resp.StatusCode}: {body}");

        var parsed = JsonSerializer.Deserialize<V2CryptoForwardResponse>(body, JsonOpts);
        return (parsed != null, parsed, parsed != null ? "OK" : "Respuesta vacía");
    }

    /// <summary>
    /// Invoca POST /api/crypto/inverse en un nodo proveedor v2.0 y abre el sobre CC-ENV-1 de resultado.enc.
    /// </summary>
    public static async Task<(bool Success, byte[]? DecryptedPlainBytes, V2ParsedZipPacket? ResultZip, string ErrorMessage)> CallRemoteInverseAsync(
        PeerNode providerPeer,
        string algorithmCode,
        string packetId,
        byte[] cipherOrPackageBytes,
        Dictionary<string, string> publicParameters,
        CcHybridEnvelope? secretEnvelope = null,
        string? keyId = null)
    {
        if (providerPeer.HasThumbprintMismatch)
            return (false, null, null, $"El nodo {providerPeer.NodeId} está bloqueado por cambio de huella TOFU.");

        string requestId = Guid.NewGuid().ToString("D").ToLowerInvariant();
        var invReq = new V2CryptoInverseRequest
        {
            RequestId = requestId,
            PacketId = packetId,
            RequesterNode = NodeRuntimeState.CurrentNodeId,
            AlgorithmCode = algorithmCode.Trim().ToUpperInvariant(),
            Operation = "inverse",
            KeyId = keyId ?? packetId,
            SecretEnvelope = secretEnvelope,
            PublicParameters = publicParameters,
            TimestampUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        };

        byte[] rawRequestBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(invReq));
        string requestSigBase64 = V2CertificateService.SignDataPss(rawRequestBytes);
        string requesterCertPem = V2CertificateService.ExportPublicCertPem();

        using var form = new MultipartFormDataContent();
        var reqContent = new ByteArrayContent(rawRequestBytes);
        reqContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        form.Add(reqContent, "request", "request.json");
        form.Add(new StringContent(requestSigBase64, Encoding.UTF8), "requestSignature");
        form.Add(new StringContent(requesterCertPem, Encoding.UTF8), "requesterCertificate");

        var payloadContent = new ByteArrayContent(cipherOrPackageBytes);
        payloadContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        form.Add(payloadContent, "payload", "datos.enc");

        string url = $"{providerPeer.BaseUrl.TrimEnd('/')}/api/crypto/inverse";
        using var httpReq = new HttpRequestMessage(HttpMethod.Post, url) { Content = form };
        AddStandardV2Headers(httpReq, requestId);

        var resp = await Http.SendAsync(httpReq);
        if (!resp.IsSuccessStatusCode)
        {
            string errBody = await resp.Content.ReadAsStringAsync();
            return (false, null, null, $"HTTP {(int)resp.StatusCode}: {errBody}");
        }

        byte[] resultZipBytes = await resp.Content.ReadAsByteArrayAsync();
        string tempResZip = Path.Combine(Path.GetTempPath(), $"RES_recv_{Guid.NewGuid():N}.zip");
        try
        {
            await File.WriteAllBytesAsync(tempResZip, resultZipBytes);
            var parsedRes = V2PacketZipService.ReadPacketZip(tempResZip, enforceStrictSignature: true);
            string envJson = Encoding.UTF8.GetString(parsedRes.PayloadBytes);
            var resultEnv = JsonSerializer.Deserialize<CcHybridEnvelope>(envJson, JsonOpts)
                ?? throw new PacketValidationException("E-ENV-DECRYPT", 400, "resultado.enc no contiene un sobre CC-ENV-1 válido.");

            byte[] plainBytes = V2EnvelopeService.Open(resultEnv, requestId);
            return (true, plainBytes, parsedRes, "OK");
        }
        finally
        {
            try { if (File.Exists(tempResZip)) File.Delete(tempResZip); } catch { }
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
                NodeId = $"EQ{Math.Clamp(port - 5000, 1, 99):D2}",
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

        var targets = new List<(string Ip, int Port)>();
        for (int host = 1; host <= 254; host++)
        {
            string ip = $"{prefix}{host}";
            for (int port = startPort; port <= endPort; port++)
                targets.Add((ip, port));
        }

        using var sem = new SemaphoreSlim(64, 64);
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
