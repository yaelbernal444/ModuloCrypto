using ModuloCrypto.Core.Models;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace ModuloCrypto.Core.Services;

/// <summary>
/// Estado global en memoria del nodo actual (EQ01 por defecto, puerto 5001), configuración de los 8 equipos y eventos de red v2.0.
/// </summary>
public static class NodeRuntimeState
{
    public const string ProtocolVersion = "2.0";
    public const int UdpDiscoveryPort = 5099;

    public static int TeamNumber { get; private set; } = 1;
    public static string CurrentNodeId { get; set; } = "EQ01";
    public static int ApiPort { get; set; } = 5001;
    public static int? HttpsPort { get; set; }
    public static bool ApiOnline { get; set; }
    public static bool SqliteConnected { get; set; }
    public static string SqliteDiagnostic { get; set; } = "Inicializando...";
    public static bool CertificateActive { get; set; }
    public static string LocalIpAddress { get; private set; } = DetectLocalIp();
    public static string SubnetBroadcastAddress { get; private set; } = DetectBroadcastAddress(LocalIpAddress);

    public static string SourceEndpoint => $"{LocalIpAddress}:{ApiPort}";

    /// <summary>
    /// Algoritmos oficiales cuyo dueño es este equipo (EQ01 -> #1 AESGCM y #2 DES).
    /// </summary>
    public static IReadOnlyList<string> OwnedAlgorithms => GetOwnedAlgorithmsForTeam(TeamNumber);

    public static List<PeerNode> NetworkPeers { get; } = CreateDefaultPeers();

    public static event Action<SolicitudEntrante>? OnPacketReceived;
    public static event Action<PeerNode>? OnPeerDiscoveredOrChanged;

    public static void ConfigureTeamAndPort(int teamNumber, int? explicitPort = null)
    {
        TeamNumber = Math.Clamp(teamNumber, 1, 99);
        CurrentNodeId = $"EQ{TeamNumber:D2}";
        ApiPort = explicitPort is > 0 and < 65536 ? explicitPort.Value : 5000 + TeamNumber;

        var selfPeer = NetworkPeers.FirstOrDefault(p => p.TeamNumber == TeamNumber || p.NodeId == CurrentNodeId);
        if (selfPeer != null)
        {
            selfPeer.NodeId = CurrentNodeId;
            selfPeer.IpAddress = "127.0.0.1";
            selfPeer.Port = ApiPort;
            selfPeer.Status = "online";
            selfPeer.Source = "local";
            selfPeer.IsConfirmed = true;
        }
    }

    public static bool IsValidNodeId(string? nodeId) =>
        !string.IsNullOrWhiteSpace(nodeId) && Regex.IsMatch(nodeId, "^EQ[0-9]{2}$");

    public static void NotifyPacketReceived(SolicitudEntrante solicitud)
    {
        OnPacketReceived?.Invoke(solicitud);
    }

    public static void NotifyPeerChanged(PeerNode peer)
    {
        OnPeerDiscoveredOrChanged?.Invoke(peer);
    }

    public static IReadOnlyList<string> GetOwnedAlgorithmsForTeam(int team) => team switch
    {
        1 => new[] { "AESGCM", "DES" },
        2 => new[] { "TRIPLEDES", "CHACHA20", "RSA" },
        3 => new[] { "ECC", "DIFFIEHELLMAN", "CAESAR" },
        4 => new[] { "VIGENERE", "XORASM", "LSBSTEGO" },
        5 => new[] { "EUCLIDESAFFINE", "MILLERRABIN", "FISHERYATES" },
        6 => new[] { "HASHSHA", "HMACSHA256", "DIGITALSIG" },
        7 => new[] { "QUANTUMPQC", "DFTSPECTRAL" },
        8 => new[] { "LAGRANGESHAMIR", "LORENZSZ40" },
        _ => new[] { "AESGCM", "DES" }
    };

    public static string GetOwnerNodeForAlgorithm(string algorithmCode)
    {
        string code = (algorithmCode ?? "").Trim().ToUpperInvariant();
        for (int t = 1; t <= 8; t++)
        {
            if (GetOwnedAlgorithmsForTeam(t).Contains(code, StringComparer.OrdinalIgnoreCase))
                return $"EQ{t:D2}";
        }
        return CurrentNodeId;
    }

    private static List<PeerNode> CreateDefaultPeers()
    {
        var peers = new List<PeerNode>();
        for (int i = 1; i <= 8; i++)
        {
            string id = $"EQ{i:D2}";
            var owned = GetOwnedAlgorithmsForTeam(i);
            peers.Add(new PeerNode
            {
                NodeId = id,
                TeamNumber = i,
                IpAddress = i == 1 ? "127.0.0.1" : $"192.168.1.{100 + i}",
                Port = 5000 + i,
                RoleLabel = $"Equipo {i:D2} ({string.Join(", ", owned)})",
                ProtocolType = "v2.0",
                Source = i == 1 ? "local" : "manual",
                Status = i == 1 ? "online" : "offline",
                AlgorithmsJson = System.Text.Json.JsonSerializer.Serialize(owned),
                IsConfirmed = i == 1
            });
        }
        return peers;
    }

    private static string DetectLocalIp()
    {
        try
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0);
            socket.Connect("8.8.8.8", 65530);
            if (socket.LocalEndPoint is IPEndPoint ep)
                return ep.Address.ToString();
        }
        catch { }
        return "127.0.0.1";
    }

    private static string DetectBroadcastAddress(string localIp)
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily == AddressFamily.InterNetwork &&
                        ua.Address.ToString() == localIp &&
                        ua.IPv4Mask != null)
                    {
                        byte[] ipBytes = ua.Address.GetAddressBytes();
                        byte[] maskBytes = ua.IPv4Mask.GetAddressBytes();
                        byte[] bcast = new byte[4];
                        for (int i = 0; i < 4; i++)
                            bcast[i] = (byte)(ipBytes[i] | (maskBytes[i] ^ 255));
                        return new IPAddress(bcast).ToString();
                    }
                }
            }
        }
        catch { }

        var parts = localIp.Split('.');
        return parts.Length == 4 && parts[0] != "127"
            ? $"{parts[0]}.{parts[1]}.{parts[2]}.255"
            : "255.255.255.255";
    }
}
