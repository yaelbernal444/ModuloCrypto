using ModuloCrypto.Core.Contracts;
using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace ModuloCrypto.Network;

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

    public static async Task<(bool Online, string Latency, NodeHealthResponse? Info)> PingNodeAsync(
        PeerNode node,
        int? customTimeoutMs = null)
    {
        var sw = Stopwatch.StartNew();

        // 1. Intentar GET /api/health (ModuloCrypto)
        try
        {
            using var cts = customTimeoutMs.HasValue
                ? new CancellationTokenSource(customTimeoutMs.Value)
                : new CancellationTokenSource(TimeSpan.FromSeconds(4));

            var resp = await Http.GetAsync($"{node.BaseUrl}/api/health", cts.Token);
            if (resp.IsSuccessStatusCode)
            {
                sw.Stop();
                string body = await resp.Content.ReadAsStringAsync(cts.Token);
                var info = JsonSerializer.Deserialize<NodeHealthResponse>(body, JsonOpts);
                if (info != null && !string.IsNullOrWhiteSpace(info.NodeId))
                {
                    node.ProtocolType = "ModuloCrypto";
                    return (true, $"{sw.ElapsedMilliseconds} ms", info);
                }
            }
        }
        catch
        {
            // Continuar al fallback /api/status
        }

        // 2. Fallback automático: GET /api/status (CentroCiberseguridad.Web)
        try
        {
            using var cts2 = customTimeoutMs.HasValue
                ? new CancellationTokenSource(customTimeoutMs.Value)
                : new CancellationTokenSource(TimeSpan.FromSeconds(4));

            var resp = await Http.GetAsync($"{node.BaseUrl}/api/status", cts2.Token);
            sw.Stop();
            if (!resp.IsSuccessStatusCode)
                return (false, "HTTP " + (int)resp.StatusCode, null);

            string body = await resp.Content.ReadAsStringAsync(cts2.Token);
            var status = JsonSerializer.Deserialize<PeerStatusResponse>(body, JsonOpts);
            if (status != null)
            {
                node.ProtocolType = "CentroCiberseguridad";
                var mapped = new NodeHealthResponse
                {
                    Status = status.Status,
                    NodeId = string.IsNullOrWhiteSpace(status.NodeId) ? node.NodeId : status.NodeId,
                    Port = node.Port,
                    X509Thumbprint = status.CertificateThumbprint ?? string.Empty,
                    SupportedAlgorithms = 21,
                    TimestampUtc = DateTime.UtcNow
                };
                return (true, $"{sw.ElapsedMilliseconds} ms", mapped);
            }

            return (false, "Respuesta inválida", null);
        }
        catch
        {
            sw.Stop();
            return (false, "Timeout", null);
        }
    }

    public static async Task<(bool Success, string Message)> SendZipPacketAsync(string targetBaseUrl, string zipPath)
    {
        var tempPeer = new PeerNode
        {
            NodeId = "NODO-DEST",
            ProtocolType = "Auto"
        };
        if (Uri.TryCreate(targetBaseUrl, UriKind.Absolute, out var uri))
        {
            tempPeer.IpAddress = uri.Host;
            tempPeer.Port = uri.Port > 0 ? uri.Port : 5000;
        }
        return await SendZipPacketAsync(tempPeer, zipPath, Guid.NewGuid().ToString());
    }

    public static async Task<(bool Success, string Message)> SendZipPacketAsync(
        PeerNode targetPeer,
        string zipPath,
        string packetId)
    {
        byte[] fileBytes = await File.ReadAllBytesAsync(zipPath);
        string fileName = Path.GetFileName(zipPath);

        bool preferCentro = string.Equals(targetPeer.ProtocolType, "CentroCiberseguridad", StringComparison.OrdinalIgnoreCase);

        var endpointsToTry = preferCentro
            ? new[]
            {
                (Path: "/api/requests/receive", Field: "package", Proto: "CentroCiberseguridad"),
                (Path: "/api/packets/receive",  Field: "file",    Proto: "ModuloCrypto")
            }
            : new[]
            {
                (Path: "/api/packets/receive",  Field: "file",    Proto: "ModuloCrypto"),
                (Path: "/api/requests/receive", Field: "package", Proto: "CentroCiberseguridad")
            };

        string lastError = string.Empty;

        foreach (var ep in endpointsToTry)
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
                    targetPeer.IsOnline = true;
                    return (true, $"Paquete enviado correctamente a {url} ({ep.Proto}).\nRespuesta HTTP {(int)resp.StatusCode}: {body}");
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
                NodeId = $"LOCAL-{port}",
                IpAddress = "127.0.0.1",
                Port = port,
                ProtocolType = "Auto"
            };

            var (online, latency, info) = await PingNodeAsync(probe, customTimeoutMs: 800);
            if (online)
            {
                probe.IsOnline = true;
                probe.LastLatency = latency;
                if (info != null)
                {
                    if (!string.IsNullOrWhiteSpace(info.NodeId))
                        probe.NodeId = info.NodeId.Trim().ToUpperInvariant();
                    if (!string.IsNullOrWhiteSpace(info.X509Thumbprint))
                        probe.CertThumbprint = info.X509Thumbprint.Length > 16
                            ? info.X509Thumbprint[..16] + "..."
                            : info.X509Thumbprint;
                }
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

        using var sem = new SemaphoreSlim(32);
        var tasks = new List<Task>(254);

        for (int host = 1; host <= 254; host++)
        {
            string ip = $"{prefix}{host}";
            tasks.Add(Task.Run(async () =>
            {
                await sem.WaitAsync();
                try
                {
                    var probe = new PeerNode
                    {
                        NodeId = $"LAN-{host}",
                        IpAddress = ip,
                        Port = port,
                        ProtocolType = "Auto"
                    };

                    var (online, latency, info) = await PingNodeAsync(probe, customTimeoutMs: 700);
                    if (online)
                    {
                        probe.IsOnline = true;
                        probe.LastLatency = latency;
                        if (info != null)
                        {
                            if (!string.IsNullOrWhiteSpace(info.NodeId))
                                probe.NodeId = info.NodeId.Trim().ToUpperInvariant();
                            if (!string.IsNullOrWhiteSpace(info.X509Thumbprint))
                                probe.CertThumbprint = info.X509Thumbprint.Length > 16
                                    ? info.X509Thumbprint[..16] + "..."
                                    : info.X509Thumbprint;
                        }
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

    public static async Task<RemoteDecryptResponse> RequestRemoteKeyAsync(string remoteDecryptUrl)
    {
        try
        {
            var resp = await Http.GetAsync(remoteDecryptUrl);
            string body = await resp.Content.ReadAsStringAsync();
            var parsed = JsonSerializer.Deserialize<RemoteDecryptResponse>(body, JsonOpts);
            if (parsed != null)
                return parsed;

            return new RemoteDecryptResponse { Success = false, Message = $"Respuesta inválida: {body}" };
        }
        catch (Exception ex)
        {
            return new RemoteDecryptResponse { Success = false, Message = $"Error al contactar nodo remoto: {ex.Message}" };
        }
    }
}
