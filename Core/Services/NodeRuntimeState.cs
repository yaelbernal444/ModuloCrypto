using ModuloCrypto.Core.Models;
using System.Net;
using System.Net.Sockets;

namespace ModuloCrypto.Core.Services;

/// <summary>
/// Estado global en memoria del nodo actual (NODO-01 por defecto), configuración de red de los 8 nodos y eventos de la API embebida.
/// </summary>
public static class NodeRuntimeState
{
    public static string CurrentNodeId { get; set; } = "NODO-01";
    public static int ApiPort { get; set; } = 5000;
    public static bool ApiOnline { get; set; }
    public static bool SqliteConnected { get; set; }
    public static bool CertificateActive { get; set; }
    public static string LocalIpAddress { get; private set; } = DetectLocalIp();

    public static List<PeerNode> NetworkPeers { get; } = CreateDefaultPeers();

    public static event Action<SolicitudEntrante>? OnPacketReceived;

    public static void NotifyPacketReceived(SolicitudEntrante solicitud)
    {
        OnPacketReceived?.Invoke(solicitud);
    }

    public static string BuildRemoteDecryptUrl(string packetId)
    {
        return $"http://{LocalIpAddress}:{ApiPort}/api/crypto/decrypt/{packetId}";
    }

    private static List<PeerNode> CreateDefaultPeers()
    {
        var peers = new List<PeerNode>();
        for (int i = 1; i <= 8; i++)
        {
            string id = $"NODO-0{i}";
            peers.Add(new PeerNode
            {
                NodeId = id,
                IpAddress = i == 1 ? "127.0.0.1" : $"192.168.1.{100 + i}",
                Port = 5000,
                RoleLabel = i == 1 ? "Nodo Local (Inicio / Relay / Final)" : "Nodo Tor (Inicio / Relay / Final)",
                ProtocolType = i == 1 ? "ModuloCrypto" : "Auto",
                IsOnline = i == 1
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
        catch
        {
            // Fallback to loopback if offline
        }
        return "127.0.0.1";
    }
}
