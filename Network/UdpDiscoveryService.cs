using ModuloCrypto.Core.Contracts;
using ModuloCrypto.Core.Data;
using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace ModuloCrypto.Network;

/// <summary>
/// Servicio de autodescubrimiento UDP en el puerto 5099 conforme al Estándar v2.0 (Punto 2):
/// - Emite CC-BEACON al iniciar y cada 30 segundos hacia 255.255.255.255:5099 y broadcast de subred.
/// - Emite CC-BEACON final con status="offline" al cerrar.
/// - Ignora anuncios propios o que no sean type="CC-BEACON" y protocolVersion="2.0".
/// - Marca nodos como offline tras 90 segundos sin beacon ni respuesta HTTP.
/// </summary>
public sealed class UdpDiscoveryService : IAsyncDisposable
{
    private const int BeaconIntervalMs = 30_000;
    private const int OfflineThresholdSeconds = 90;
    private const int MaxBeaconBytes = 1024;

    private UdpClient? _udpListener;
    private CancellationTokenSource? _cts;
    private Task? _listenTask;
    private Task? _loopTask;

    public void Start()
    {
        if (_cts != null) return;
        _cts = new CancellationTokenSource();

        try
        {
            _udpListener = new UdpClient();
            _udpListener.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            _udpListener.EnableBroadcast = true;
            _udpListener.Client.Bind(new IPEndPoint(IPAddress.Any, NodeRuntimeState.UdpDiscoveryPort));

            _listenTask = Task.Run(() => ListenLoopAsync(_cts.Token));
        }
        catch
        {
            // Si otro proceso local ya ocupó 5099 sin permitir reuso, continuamos con emisión y escaneo HTTP
        }

        _loopTask = Task.Run(() => BeaconAndHealthLoopAsync(_cts.Token));
    }

    public async Task SendBeaconAsync(string status = "online")
    {
        try
        {
            var beacon = new CcBeaconMessage
            {
                Type = "CC-BEACON",
                ProtocolVersion = "2.0",
                NodeId = NodeRuntimeState.CurrentNodeId,
                TeamNumber = NodeRuntimeState.TeamNumber,
                Ip = NodeRuntimeState.LocalIpAddress,
                HttpPort = NodeRuntimeState.ApiPort,
                HttpsPort = NodeRuntimeState.HttpsPort,
                Status = status,
                Algorithms = NodeRuntimeState.OwnedAlgorithms.ToList(),
                CertificateThumbprintSha256 = NodeCertificateService.GetThumbprintSha256Hex(),
                TimestampUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
            };

            string json = JsonSerializer.Serialize(beacon);
            byte[] payload = Encoding.UTF8.GetBytes(json);
            if (payload.Length > MaxBeaconBytes) return;

            using var sender = new UdpClient { EnableBroadcast = true };
            await sender.SendAsync(payload, payload.Length, new IPEndPoint(IPAddress.Broadcast, NodeRuntimeState.UdpDiscoveryPort));

            if (NodeRuntimeState.SubnetBroadcastAddress != "255.255.255.255" &&
                IPAddress.TryParse(NodeRuntimeState.SubnetBroadcastAddress, out var subnetBcast))
            {
                await sender.SendAsync(payload, payload.Length, new IPEndPoint(subnetBcast, NodeRuntimeState.UdpDiscoveryPort));
            }
        }
        catch { }
    }

    private async Task BeaconAndHealthLoopAsync(CancellationToken ct)
    {
        await SendBeaconAsync("online");

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(BeaconIntervalMs, ct);
                await SendBeaconAsync("online");
                await CheckStalePeersAsync();
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch { }
        }
    }

    private async Task ListenLoopAsync(CancellationToken ct)
    {
        if (_udpListener == null) return;

        while (!ct.IsCancellationRequested)
        {
            try
            {
                var result = await _udpListener.ReceiveAsync(ct);
                if (result.Buffer.Length == 0 || result.Buffer.Length > MaxBeaconBytes)
                    continue;

                string json = Encoding.UTF8.GetString(result.Buffer);
                var beacon = JsonSerializer.Deserialize<CcBeaconMessage>(json, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

                if (beacon == null) continue;
                await ProcessIncomingBeaconAsync(beacon, result.RemoteEndPoint.Address.ToString());
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch { }
        }
    }

    public static async Task<bool> ProcessIncomingBeaconAsync(CcBeaconMessage beacon, string? senderIp = null)
    {
        if (!string.Equals(beacon.Type, "CC-BEACON", StringComparison.Ordinal) ||
            !string.Equals(beacon.ProtocolVersion, "2.0", StringComparison.Ordinal))
        {
            return false;
        }

        if (!NodeRuntimeState.IsValidNodeId(beacon.NodeId))
            return false;

        // Ignorar anuncios propios
        if (string.Equals(beacon.NodeId, NodeRuntimeState.CurrentNodeId, StringComparison.OrdinalIgnoreCase) &&
            beacon.HttpPort == NodeRuntimeState.ApiPort)
        {
            return false;
        }

        string ip = !string.IsNullOrWhiteSpace(beacon.Ip) && beacon.Ip != "0.0.0.0"
            ? beacon.Ip
            : (senderIp ?? "127.0.0.1");

        var peer = NodeRuntimeState.NetworkPeers.FirstOrDefault(p =>
            p.NodeId.Equals(beacon.NodeId, StringComparison.OrdinalIgnoreCase));

        if (peer == null)
        {
            peer = new PeerNode
            {
                NodeId = beacon.NodeId.ToUpperInvariant(),
                TeamNumber = beacon.TeamNumber,
                IpAddress = ip,
                Port = beacon.HttpPort,
                HttpsPort = beacon.HttpsPort,
                Source = "beacon",
                ProtocolType = "v2.0"
            };
            NodeRuntimeState.NetworkPeers.Add(peer);
        }

        peer.TeamNumber = beacon.TeamNumber > 0 ? beacon.TeamNumber : peer.TeamNumber;
        peer.IpAddress = ip;
        peer.Port = beacon.HttpPort > 0 ? beacon.HttpPort : peer.Port;
        peer.HttpsPort = beacon.HttpsPort;
        peer.Source = "beacon";
        peer.LastSeenUtc = DateTime.UtcNow;

        if (beacon.Algorithms is { Count: > 0 })
        {
            peer.AlgorithmsJson = JsonSerializer.Serialize(beacon.Algorithms);
            peer.RoleLabel = $"Equipo {peer.TeamNumber:D2} ({string.Join(", ", beacon.Algorithms)})";
        }

        if (string.Equals(beacon.Status, "offline", StringComparison.OrdinalIgnoreCase))
        {
            if (peer.Status != "blocked")
                peer.Status = "offline";
            AppDbContext.UpsertTrustedPeer(peer);
            NodeRuntimeState.NotifyPeerChanged(peer);
            return true;
        }

        // Verificar huella TOFU contra PinnedThumbprintSha256
        string incomingThumb = (beacon.CertificateThumbprintSha256 ?? "").Trim().ToUpperInvariant();
        NodeNetworkClient.ApplyTofuThumbprintCheck(peer, incomingThumb);

        // Si aún no tenemos su PEM o está online, consultar /api/certificate en segundo plano
        if (!peer.HasThumbprintMismatch && string.IsNullOrWhiteSpace(peer.CertificatePem))
        {
            _ = Task.Run(async () =>
            {
                await NodeNetworkClient.FetchAndValidatePeerCertificateAsync(peer);
                AppDbContext.UpsertTrustedPeer(peer);
                NodeRuntimeState.NotifyPeerChanged(peer);
            });
        }
        else
        {
            AppDbContext.UpsertTrustedPeer(peer);
            NodeRuntimeState.NotifyPeerChanged(peer);
        }

        return true;
    }

    private static async Task CheckStalePeersAsync()
    {
        DateTime now = DateTime.UtcNow;
        foreach (var peer in NodeRuntimeState.NetworkPeers.ToList())
        {
            if (peer.NodeId == NodeRuntimeState.CurrentNodeId) continue;
            if (peer.Status == "blocked") continue;

            if ((now - peer.LastSeenUtc).TotalSeconds > OfflineThresholdSeconds)
            {
                var (online, _, _) = await NodeNetworkClient.PingNodeAsync(peer, customTimeoutMs: 500);
                if (!online)
                {
                    peer.Status = "offline";
                    AppDbContext.UpsertTrustedPeer(peer);
                    NodeRuntimeState.NotifyPeerChanged(peer);
                }
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        await SendBeaconAsync("offline");

        if (_cts != null)
        {
            _cts.Cancel();
            _cts.Dispose();
            _cts = null;
        }

        try { _udpListener?.Close(); _udpListener?.Dispose(); } catch { }
        _udpListener = null;
    }
}
