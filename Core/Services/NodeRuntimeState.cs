using ModuloCrypto.Core.Data;
using ModuloCrypto.Core.Models;
using ModuloCrypto.Network.Shared;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ModuloCrypto.Core.Services;

public enum ProtocolVersionMode
{
    V1 = 1,
    V2 = 2
}

/// <summary>
/// Estado global en memoria del nodo activo. Soporta conmutación limpia entre:
/// - Versión 1.0 (Legado ModuloCrypto: NODO-01, puerto 5000, ZIP híbrido 5 archivos)
/// - Versión 2.0 (Estándar Interoperable: EQ01..EQ08, puerto 5001..5008, UDP 5099, CC-ENV-1, ZIP estricto 3 archivos)
/// </summary>
public static class NodeRuntimeState
{
    public const int UdpDiscoveryPort = 5099;

    public static ProtocolVersionMode ActiveProtocolVersion { get; private set; } = ProtocolVersionMode.V2;
    public static bool IsV2 => ActiveProtocolVersion == ProtocolVersionMode.V2;
    public static string ProtocolVersion => IsV2 ? "2.0" : "1.0";

    public static int TeamNumber { get; private set; } = 1;
    public static string CurrentNodeId { get; set; } = "EQ01";
    public static int ApiPort { get; set; } = 5001;
    public static int? HttpsPort { get; set; }
    public static bool ApiOnline { get; set; }
    public static bool SqliteConnected { get; set; }
    public static string SqliteDiagnostic { get; set; } = "Inicializando...";
    public static bool CertificateActive { get; set; }

    public static string ActiveInterfaceName { get; private set; } = "LAN";
    public static string LocalIpAddress { get; private set; } = "127.0.0.1";
    public static string LocalSubnetMask { get; private set; } = "255.255.255.0";
    public static string SubnetBroadcastAddress { get; private set; } = "255.255.255.255";
    public static bool IsLoopbackFallback { get; private set; }

    public static string SourceEndpoint => $"{LocalIpAddress}:{ApiPort}";

    public static INodeProtocolRuntime? ActiveRuntime { get; set; }

    /// <summary>
    /// Algoritmos oficiales cuyo dueño es este equipo en v2.0 (EQ01 -> #1 AESGCM y #2 DES).
    /// </summary>
    public static IReadOnlyList<string> OwnedAlgorithms => GetOwnedAlgorithmsForTeam(TeamNumber);

    public static List<PeerNode> NetworkPeers { get; } = new();

    private static readonly object NetworkLogLock = new();
    private static readonly List<string> NetworkLogBuffer = new();
    private const int MaxNetworkLogEntries = 200;

    public static event Action<SolicitudEntrante>? OnPacketReceived;
    public static event Action<PeerNode>? OnPeerDiscoveredOrChanged;
    public static event Action<LocalNetworkEndpoint>? OnActiveEndpointUpdated;
    public static event Action<string>? OnNetworkLogAdded;

    static NodeRuntimeState()
    {
        var primary = NetworkAddressService.GetPrimaryIpv4();
        UpdateActiveNetworkEndpoint(primary);
        RebuildPeersForCurrentMode();
    }

    public static void UpdateActiveNetworkEndpoint(LocalNetworkEndpoint endpoint)
    {
        ActiveInterfaceName = endpoint.InterfaceName;
        LocalIpAddress = endpoint.Ipv4Address;
        LocalSubnetMask = string.IsNullOrWhiteSpace(endpoint.SubnetMask) ? "255.255.255.0" : endpoint.SubnetMask;
        SubnetBroadcastAddress = endpoint.BroadcastAddress;
        IsLoopbackFallback = endpoint.IsLoopbackFallback;
        OnActiveEndpointUpdated?.Invoke(endpoint);
    }

    public static void ConfigureForMode(ProtocolVersionMode mode, int teamNumber = 1, int? explicitPort = null)
    {
        ActiveProtocolVersion = mode;
        TeamNumber = Math.Clamp(teamNumber, 1, 99);

        if (mode == ProtocolVersionMode.V1)
        {
            CurrentNodeId = $"NODO-{TeamNumber:D2}";
            ApiPort = explicitPort is > 0 and < 65536 ? explicitPort.Value : 5000;
            HttpsPort = null;
        }
        else
        {
            CurrentNodeId = $"EQ{TeamNumber:D2}";
            ApiPort = explicitPort is > 0 and < 65536 ? explicitPort.Value : (5000 + TeamNumber);
            HttpsPort = null;
        }

        RebuildPeersForCurrentMode();
    }

    public static void ConfigureTeamAndPort(int teamNumber, int? explicitPort = null)
    {
        ConfigureForMode(ActiveProtocolVersion, teamNumber, explicitPort);
    }

    public static void RebuildPeersForCurrentMode()
    {
        NetworkPeers.Clear();
        string subnetPrefix = GetSubnetPrefix(LocalIpAddress);

        if (ActiveProtocolVersion == ProtocolVersionMode.V1)
        {
            var rolesV1 = new[]
            {
                "Raíz / Inicio / Final",
                "Salto Intermedio Tor",
                "Salto Intermedio Tor",
                "Salto Intermedio Tor",
                "Validador X.509",
                "Auditor de Paquetes",
                "Concentrador Cripto",
                "Nodo Destino Final"
            };

            for (int i = 1; i <= 8; i++)
            {
                string id = $"NODO-{i:D2}";
                bool isSelf = i == TeamNumber;
                NetworkPeers.Add(new PeerNode
                {
                    NodeId = id,
                    TeamNumber = i,
                    IpAddress = isSelf ? LocalIpAddress : $"{subnetPrefix}{100 + i}",
                    Port = isSelf ? ApiPort : 5000,
                    RoleLabel = rolesV1[i - 1],
                    ProtocolType = "v1.0",
                    Source = isSelf ? "local" : "manual",
                    Status = isSelf ? "online" : "offline",
                    AlgorithmsJson = "[\"21-ALGORITMOS\"]",
                    IsConfirmed = true
                });
            }
        }
        else
        {
            for (int i = 1; i <= 8; i++)
            {
                string id = $"EQ{i:D2}";
                bool isSelf = i == TeamNumber;
                var owned = GetOwnedAlgorithmsForTeam(i);
                NetworkPeers.Add(new PeerNode
                {
                    NodeId = id,
                    TeamNumber = i,
                    IpAddress = isSelf ? LocalIpAddress : $"{subnetPrefix}{100 + i}",
                    Port = isSelf ? ApiPort : (5000 + i),
                    RoleLabel = $"Equipo {i:D2} ({string.Join(", ", owned)})",
                    ProtocolType = "v2.0",
                    Source = isSelf ? "local" : "manual",
                    Status = isSelf ? "online" : "offline",
                    AlgorithmsJson = JsonSerializer.Serialize(owned),
                    IsConfirmed = isSelf
                });
            }

            try
            {
                using var db = new AppDbContext();
                AppDbContext.LoadPersistedPeersIntoRuntime(db);
            }
            catch { }
        }
    }

    private static string GetSubnetPrefix(string ip)
    {
        var parts = (ip ?? "").Split('.');
        return parts.Length == 4 && parts[0] != "127"
            ? $"{parts[0]}.{parts[1]}.{parts[2]}."
            : "192.168.1.";
    }

    public static bool IsValidNodeId(string? nodeId) =>
        !string.IsNullOrWhiteSpace(nodeId) && Regex.IsMatch(nodeId, "^EQ[0-9]{2}$");

    public static bool IsValidAnyVersionNodeId(string? nodeId) =>
        !string.IsNullOrWhiteSpace(nodeId) &&
        (Regex.IsMatch(nodeId, "^EQ[0-9]{2}$") || Regex.IsMatch(nodeId, "^NODO-[0-9]{2}$", RegexOptions.IgnoreCase));

    public static void NotifyPacketReceived(SolicitudEntrante solicitud)
    {
        OnPacketReceived?.Invoke(solicitud);
    }

    public static void NotifyPeerChanged(PeerNode peer)
    {
        OnPeerDiscoveredOrChanged?.Invoke(peer);
    }

    public static void AddNetworkLog(string ip, string nodeId, string endpoint, int httpStatus, string codeOrDetail)
    {
        string cleanIp = string.IsNullOrWhiteSpace(ip) ? "127.0.0.1" : ip.Trim();
        string cleanNode = string.IsNullOrWhiteSpace(nodeId) ? "??" : nodeId.Trim();
        string cleanEp = string.IsNullOrWhiteSpace(endpoint) ? "/" : endpoint.Trim();
        string line = $"[{DateTime.Now:HH:mm:ss}] {cleanIp} {cleanNode} {cleanEp} -> HTTP {httpStatus} {codeOrDetail}";

        lock (NetworkLogLock)
        {
            NetworkLogBuffer.Add(line);
            if (NetworkLogBuffer.Count > MaxNetworkLogEntries)
                NetworkLogBuffer.RemoveAt(0);
        }

        OnNetworkLogAdded?.Invoke(line);
    }

    public static IReadOnlyList<string> GetNetworkLogsSnapshot()
    {
        lock (NetworkLogLock)
        {
            return NetworkLogBuffer.ToList();
        }
    }

    public static void ClearNetworkLogs()
    {
        lock (NetworkLogLock)
        {
            NetworkLogBuffer.Clear();
        }
    }

    /// <summary>
    /// Tabla 4.1 exacta del Estándar de Comunicación v2.0 (2 algoritmos oficiales por equipo EQ01–EQ08).
    /// </summary>
    public static IReadOnlyList<string> GetOwnedAlgorithmsForTeam(int team) => team switch
    {
        1 => new[] { "AESGCM", "DES" },
        2 => new[] { "TRIPLEDES", "CHACHA20" },
        3 => new[] { "RSA", "ECC" },
        4 => new[] { "DIFFIEHELLMAN", "CAESAR" },
        5 => new[] { "VIGENERE", "XORASM" },
        6 => new[] { "LSBSTEGO", "EUCLIDESAFFINE" },
        7 => new[] { "MILLERRABIN", "FISHERYATES" },
        8 => new[] { "HASHSHA", "HMACSHA256" },
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

        // Algoritmos locales adicionales (17–21) fuera de los pares base de Tabla 4.1
        return code switch
        {
            "DIGITALSIG" => "EQ06",
            "QUANTUMPQC" or "DFTSPECTRAL" => "EQ07",
            "LAGRANGESHAMIR" or "LORENZSZ40" => "EQ08",
            _ => CurrentNodeId
        };
    }
}
