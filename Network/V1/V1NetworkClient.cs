using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text.Json;

namespace ModuloCrypto.Network.V1;

/// <summary>
/// Cliente HTTP de la Versión 1.0 (Legado ModuloCrypto + compatibilidad CentroCiberseguridad.Web v1).
/// Usa SocketsHttpHandler optimizado, ping dual (/api/health y /api/status), envío dual (/api/packets/receive y /api/requests/receive),
/// escaneo LAN /24 en la subred de la IP activa, escaneo localhost 5000–5008 y RequestRemoteKeyAsync.
/// </summary>
public static class V1NetworkClient
{
    private static readonly HttpClient Http = new(new SocketsHttpHandler
    {
        PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        ConnectTimeout = TimeSpan.FromSeconds(3)
    })
    {
        Timeout = TimeSpan.FromSeconds(10)
    };

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public static async Task<(bool Online, string Latency, V1NodeHealthResponse? Info)> PingNodeAsync(
        PeerNode node,
        int? customTimeoutMs = null)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            using var cts = new CancellationTokenSource(customTimeoutMs ?? 2000);
            var resp = await Http.GetAsync($"{node.BaseUrl}/api/health", cts.Token);
            if (resp.IsSuccessStatusCode)
            {
                sw.Stop();
                string json = await resp.Content.ReadAsStringAsync(cts.Token);
                var info = JsonSerializer.Deserialize<V1NodeHealthResponse>(json, JsonOpts);
                node.ProtocolType = "ModuloCrypto v1.0";
                node.Status = "online";
                node.LastLatency = $"{sw.ElapsedMilliseconds} ms";
                if (info != null && !string.IsNullOrWhiteSpace(info.X509Thumbprint))
                    node.CertThumbprint = info.X509Thumbprint;
                return (true, node.LastLatency, info);
            }
        }
        catch { }

        try
        {
            using var cts2 = new CancellationTokenSource(customTimeoutMs ?? 2000);
            var resp2 = await Http.GetAsync($"{node.BaseUrl}/api/status", cts2.Token);
            sw.Stop();
            if (resp2.IsSuccessStatusCode)
            {
                string json = await resp2.Content.ReadAsStringAsync(cts2.Token);
                var peerStatus = JsonSerializer.Deserialize<V1PeerStatusResponse>(json, JsonOpts);
                node.ProtocolType = "CentroCiberseguridad v1";
                node.Status = "online";
                node.LastLatency = $"{sw.ElapsedMilliseconds} ms";
                if (peerStatus != null && !string.IsNullOrWhiteSpace(peerStatus.CertificateThumbprint))
                    node.CertThumbprint = peerStatus.CertificateThumbprint;
                var info = new V1NodeHealthResponse
                {
                    Status = "Online",
                    NodeId = peerStatus?.NodeId ?? node.NodeId,
                    Port = node.Port,
                    X509Thumbprint = peerStatus?.CertificateThumbprint ?? string.Empty
                };
                return (true, node.LastLatency, info);
            }
        }
        catch { }

        sw.Stop();
        node.Status = "offline";
        node.LastLatency = "Timeout";
        return (false, "Timeout", null);
    }

    public static async Task<(bool Success, string Message)> SendZipPacketAsync(
        PeerNode targetPeer,
        string zipPath,
        string packetId)
    {
        byte[] fileBytes = await File.ReadAllBytesAsync(zipPath);
        string fileName = Path.GetFileName(zipPath);

        bool preferCentro = string.Equals(targetPeer.ProtocolType, "CentroCiberseguridad v1", StringComparison.OrdinalIgnoreCase);

        var endpoints = preferCentro
            ? new[]
            {
                (Path: "/api/requests/receive", Field: "package", Proto: "CentroCiberseguridad v1"),
                (Path: "/api/packets/receive",  Field: "file",    Proto: "ModuloCrypto v1.0")
            }
            : new[]
            {
                (Path: "/api/packets/receive",  Field: "file",    Proto: "ModuloCrypto v1.0"),
                (Path: "/api/requests/receive", Field: "package", Proto: "CentroCiberseguridad v1")
            };

        string lastError = "Sin respuesta";

        foreach (var ep in endpoints)
        {
            string url = targetPeer.BaseUrl.TrimEnd('/') + ep.Path;
            try
            {
                using var form = new MultipartFormDataContent();
                var content = new ByteArrayContent(fileBytes);
                content.Headers.ContentType = new MediaTypeHeaderValue("application/zip");
                form.Add(content, ep.Field, fileName);

                using var req = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = form
                };
                req.Headers.TryAddWithoutValidation("X-Source-Node", NodeRuntimeState.CurrentNodeId);
                req.Headers.TryAddWithoutValidation("X-Packet-Id", packetId);

                var resp = await Http.SendAsync(req);
                string body = await resp.Content.ReadAsStringAsync();

                if (resp.IsSuccessStatusCode)
                {
                    targetPeer.ProtocolType = ep.Proto;
                    targetPeer.Status = "online";
                    return (true, $"Paquete v1.0 enviado a {url} ({ep.Proto}).\nRespuesta HTTP {(int)resp.StatusCode}: {body}");
                }

                lastError = $"HTTP {(int)resp.StatusCode} en {url}: {body}";
            }
            catch (Exception ex)
            {
                lastError = $"Error hacia {url}: {ex.Message}";
            }
        }

        return (false, $"No se pudo entregar el paquete a {targetPeer.BaseUrl}.\nDetalle: {lastError}");
    }

    public static async Task<List<PeerNode>> ScanLocalhostPortsAsync(int startPort = 5000, int endPort = 5008)
    {
        var found = new ConcurrentBag<PeerNode>();
        var ports = Enumerable.Range(startPort, Math.Max(1, endPort - startPort + 1));

        await Parallel.ForEachAsync(ports, async (port, _) =>
        {
            var probe = new PeerNode
            {
                NodeId = $"NODO-{Math.Clamp(port - 4999, 1, 99):D2}",
                IpAddress = "127.0.0.1",
                Port = port,
                ProtocolType = "v1.0",
                Source = "scan"
            };

            var (online, latency, info) = await PingNodeAsync(probe, customTimeoutMs: 700);
            if (online)
            {
                probe.LastLatency = latency;
                if (info != null && !string.IsNullOrWhiteSpace(info.NodeId))
                    probe.NodeId = info.NodeId.Trim().ToUpperInvariant();
                found.Add(probe);
            }
        });

        return found.OrderBy(p => p.Port).ToList();
    }

    public static async Task<List<PeerNode>> ScanLanSubnetAsync(string localIp, int port = 5000)
    {
        var found = new ConcurrentBag<PeerNode>();
        string prefix = "192.168.1.";

        var parts = (localIp ?? "").Split('.');
        if (parts.Length == 4 && parts[0] != "127")
            prefix = $"{parts[0]}.{parts[1]}.{parts[2]}.";

        using var sem = new SemaphoreSlim(48);
        var tasks = new List<Task>(254);

        for (int host = 1; host <= 254; host++)
        {
            string ip = $"{prefix}{host}";
            int capturedHost = host;
            tasks.Add(Task.Run(async () =>
            {
                await sem.WaitAsync();
                try
                {
                    var probe = new PeerNode
                    {
                        NodeId = $"LAN-{capturedHost}",
                        IpAddress = ip,
                        Port = port,
                        ProtocolType = "v1.0",
                        Source = "scan"
                    };

                    var (online, latency, info) = await PingNodeAsync(probe, customTimeoutMs: 600);
                    if (online)
                    {
                        probe.LastLatency = latency;
                        if (info != null && !string.IsNullOrWhiteSpace(info.NodeId))
                            probe.NodeId = info.NodeId.Trim().ToUpperInvariant();
                        found.Add(probe);
                    }
                }
                finally
                {
                    sem.Release();
                }
            }));
        }

        await Task.WhenAll(tasks);
        return found.OrderBy(p => p.IpAddress).ToList();
    }

    public static async Task<V1RemoteDecryptResponse> RequestRemoteKeyAsync(string remoteDecryptUrl)
    {
        try
        {
            var resp = await Http.GetAsync(remoteDecryptUrl);
            string body = await resp.Content.ReadAsStringAsync();
            var parsed = JsonSerializer.Deserialize<V1RemoteDecryptResponse>(body, JsonOpts);
            if (parsed != null)
                return parsed;

            return new V1RemoteDecryptResponse { Success = false, Message = $"Respuesta inválida: {body}" };
        }
        catch (Exception ex)
        {
            return new V1RemoteDecryptResponse { Success = false, Message = $"Error al contactar nodo remoto: {ex.Message}" };
        }
    }
}
