using ModuloCrypto.Core.Services;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace ModuloCrypto.Network.Shared;

public sealed class ConnectivityDiagnosticReport
{
    public string TargetIp { get; init; } = string.Empty;
    public int TargetPort { get; init; }
    public bool IcmpPingSuccess { get; init; }
    public long IcmpRoundtripMs { get; init; }
    public string IcmpStatusDetail { get; init; } = string.Empty;
    public bool TcpPortOpen { get; init; }
    public long TcpConnectMs { get; init; }
    public string TcpStatusDetail { get; init; } = string.Empty;
    public bool HttpApiSuccess { get; init; }
    public long HttpLatencyMs { get; init; }
    public string DetectedNodeId { get; init; } = string.Empty;
    public string DetectedProtocolVersion { get; init; } = string.Empty;
    public string DetectedThumbprint { get; init; } = string.Empty;
    public bool HasVersionMismatch { get; init; }
    public string SummaryTitle { get; init; } = string.Empty;
    public string FullFormattedReport { get; init; } = string.Empty;
}

/// <summary>
/// Diagnóstico secuencial de 3 capas (1. Ping ICMP, 2. Socket TCP, 3. HTTP /api/status + /api/certificate)
/// para distinguir red inalcanzable, firewall bloqueando puerto o choque de versiones (v1.0 vs v2.0).
/// </summary>
public static class ConnectivityDiagnostics
{
    private static readonly HttpClient DiagHttp = new(new SocketsHttpHandler
    {
        PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        ConnectTimeout = TimeSpan.FromSeconds(2)
    })
    {
        Timeout = TimeSpan.FromSeconds(3)
    };

    public static async Task<ConnectivityDiagnosticReport> RunFullDiagnosticAsync(
        string ipAddress,
        int port,
        ProtocolVersionMode activeLocalVersion)
    {
        string cleanIp = (ipAddress ?? "127.0.0.1").Trim();
        int cleanPort = Math.Clamp(port, 1, 65535);
        string localVerStr = activeLocalVersion == ProtocolVersionMode.V2 ? "2.0" : "1.0";

        // 1. Capa 1: Ping ICMP
        bool icmpOk = false;
        long icmpMs = 0;
        string icmpDetail;
        try
        {
            using var pinger = new Ping();
            var reply = await pinger.SendPingAsync(cleanIp, 1500);
            if (reply.Status == IPStatus.Success)
            {
                icmpOk = true;
                icmpMs = reply.RoundtripTime;
                icmpDetail = $"✓ Respuesta ICMP recibida en {icmpMs} ms ({reply.Address})";
            }
            else
            {
                icmpDetail = $"⚠ Sin respuesta ICMP ({reply.Status}) — puede deberse a host apagado o ICMP bloqueado por Windows Firewall";
            }
        }
        catch (Exception ex)
        {
            icmpDetail = $"✕ Error ICMP: {ex.Message}";
        }

        // 2. Capa 2: Socket TCP al puerto destino (timeout 2 s)
        bool tcpOk = false;
        long tcpMs = 0;
        string tcpDetail;
        var swTcp = Stopwatch.StartNew();
        try
        {
            using var tcp = new TcpClient();
            using var cts = new CancellationTokenSource(2000);
            await tcp.ConnectAsync(cleanIp, cleanPort, cts.Token);
            swTcp.Stop();
            tcpOk = true;
            tcpMs = swTcp.ElapsedMilliseconds;
            tcpDetail = $"✓ Puerto TCP {cleanPort} ABIERTO ({tcpMs} ms)";
        }
        catch (Exception ex)
        {
            swTcp.Stop();
            tcpDetail = icmpOk
                ? $"✕ El host {cleanIp} responde en red, pero el puerto TCP {cleanPort} está CERRADO o bloqueado por Firewall ({ex.GetType().Name})"
                : $"✕ No se pudo conectar a {cleanIp}:{cleanPort} — Red/IP inalcanzable o equipo apagado";
        }

        // 3. Capa 3: Sondeo HTTP (/api/status y /api/health, más /api/certificate en v2)
        bool httpOk = false;
        long httpMs = 0;
        string detectedNode = "Desconocido";
        string detectedVer = "Desconocida";
        string detectedThumb = "N/D";
        bool versionMismatch = false;
        string httpDetail = "No ejecutado (puerto TCP cerrado).";

        if (tcpOk)
        {
            string baseUrl = $"http://{cleanIp}:{cleanPort}";
            var swHttp = Stopwatch.StartNew();
            try
            {
                using var cts = new CancellationTokenSource(2500);
                var statusResp = await DiagHttp.GetAsync($"{baseUrl}/api/status", cts.Token);
                swHttp.Stop();
                httpMs = swHttp.ElapsedMilliseconds;

                if (statusResp.IsSuccessStatusCode)
                {
                    httpOk = true;
                    string json = await statusResp.Content.ReadAsStringAsync(cts.Token);
                    using var doc = JsonDocument.Parse(json);
                    var root = doc.RootElement;

                    if (root.TryGetProperty("nodeId", out var nProp))
                        detectedNode = nProp.GetString() ?? detectedNode;
                    if (root.TryGetProperty("protocolVersion", out var vProp))
                        detectedVer = vProp.GetString() ?? "1.0";
                    if (root.TryGetProperty("certificateThumbprintSha256", out var t2Prop))
                        detectedThumb = t2Prop.GetString() ?? detectedThumb;
                    else if (root.TryGetProperty("certificateThumbprint", out var t1Prop))
                        detectedThumb = t1Prop.GetString() ?? detectedThumb;
                }
                else
                {
                    // Intentar /api/health (nativo V1)
                    var healthResp = await DiagHttp.GetAsync($"{baseUrl}/api/health", cts.Token);
                    if (healthResp.IsSuccessStatusCode)
                    {
                        httpOk = true;
                        string json = await healthResp.Content.ReadAsStringAsync(cts.Token);
                        using var doc = JsonDocument.Parse(json);
                        var root = doc.RootElement;
                        detectedVer = "1.0";
                        if (root.TryGetProperty("nodeId", out var nProp) || root.TryGetProperty("NodeId", out nProp))
                            detectedNode = nProp.GetString() ?? detectedNode;
                        if (root.TryGetProperty("x509Thumbprint", out var tProp) || root.TryGetProperty("X509Thumbprint", out tProp))
                            detectedThumb = tProp.GetString() ?? detectedThumb;
                    }
                    else
                    {
                        httpDetail = $"✕ HTTP {(int)statusResp.StatusCode} en {baseUrl}/api/status";
                    }
                }

                if (httpOk)
                {
                    versionMismatch = !string.Equals(detectedVer, localVerStr, StringComparison.OrdinalIgnoreCase);
                    httpDetail = $"✓ API activa en {baseUrl} ({httpMs} ms) • Nodo: {detectedNode} • Protocolo remoto: v{detectedVer}";

                    if (string.Equals(detectedVer, "2.0", StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            var certResp = await DiagHttp.GetAsync($"{baseUrl}/api/certificate", cts.Token);
                            if (certResp.IsSuccessStatusCode)
                            {
                                string ctype = certResp.Content.Headers.ContentType?.MediaType ?? "application/x-pem-file";
                                httpDetail += $" • /api/certificate OK ({ctype})";
                            }
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                swHttp.Stop();
                httpDetail = $"✕ Falló consulta HTTP a {baseUrl}: {ex.Message}";
            }
        }

        string summaryTitle;
        if (!tcpOk)
        {
            summaryTitle = icmpOk
                ? "BLOQUEO DE PUERTO / SERVICIO APAGADO"
                : "RED O IP INALCANZABLE";
        }
        else if (!httpOk)
        {
            summaryTitle = "PUERTO ABIERTO PERO API NO RESPONDE";
        }
        else if (versionMismatch)
        {
            summaryTitle = $"CHOQUE DE VERSIÓN DETECTADO (Local v{localVerStr} ≠ Remoto v{detectedVer})";
        }
        else
        {
            summaryTitle = $"CONEXIÓN ÓPTIMA CON {detectedNode} (Protocolo v{detectedVer})";
        }

        var sb = new StringBuilder();
        sb.AppendLine($"Diagnóstico hacia {cleanIp}:{cleanPort}");
        sb.AppendLine($"Estado General : {summaryTitle}");
        sb.AppendLine(new string('─', 58));
        sb.AppendLine($"1. Ping ICMP   : {icmpDetail}");
        sb.AppendLine($"2. Socket TCP  : {tcpDetail}");
        sb.AppendLine($"3. API HTTP    : {httpDetail}");
        if (httpOk)
        {
            string shortThumb = detectedThumb.Length > 24 ? detectedThumb[..24] + "..." : detectedThumb;
            sb.AppendLine($"   • Huella X.509 : {shortThumb}");
        }

        if (versionMismatch)
        {
            sb.AppendLine();
            sb.AppendLine($"🚨 ALERTA DE COMPATIBILIDAD DE VERSIÓN:");
            sb.AppendLine($"Tu sesión actual está en Versión {localVerStr} ({NodeRuntimeState.CurrentNodeId}), pero el nodo en {cleanIp}:{cleanPort} opera en Versión {detectedVer} ({detectedNode}).");
            sb.AppendLine($"Para interoperar con ese nodo sin rechazos, cierra sesión y selecciona 'Versión {detectedVer}' en la pantalla de Login.");
        }
        else if (!tcpOk && icmpOk)
        {
            sb.AppendLine();
            sb.AppendLine($"💡 SUGERENCIA TÉCNICA:");
            sb.AppendLine($"La PC destino ({cleanIp}) sí está en la misma red LAN, pero el puerto {cleanPort} no acepta conexiones.");
            sb.AppendLine($"Verifica que ModuloCrypto haya iniciado sesión en esa PC en el puerto {cleanPort} y que el Firewall de Windows permita tráfico entrante en el puerto TCP {cleanPort}.");
        }

        return new ConnectivityDiagnosticReport
        {
            TargetIp = cleanIp,
            TargetPort = cleanPort,
            IcmpPingSuccess = icmpOk,
            IcmpRoundtripMs = icmpMs,
            IcmpStatusDetail = icmpDetail,
            TcpPortOpen = tcpOk,
            TcpConnectMs = tcpMs,
            TcpStatusDetail = tcpDetail,
            HttpApiSuccess = httpOk,
            HttpLatencyMs = httpMs,
            DetectedNodeId = detectedNode,
            DetectedProtocolVersion = detectedVer,
            DetectedThumbprint = detectedThumb,
            HasVersionMismatch = versionMismatch,
            SummaryTitle = summaryTitle,
            FullFormattedReport = sb.ToString()
        };
    }
}
