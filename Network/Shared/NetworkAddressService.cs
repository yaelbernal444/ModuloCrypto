using ModuloCrypto.Core.Data;
using ModuloCrypto.Core.Services;
using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Numerics;
using System.Text.Json;

namespace ModuloCrypto.Network.Shared;

public sealed record SubnetScanPlan(
    string NetworkAddress,
    string BroadcastAddress,
    int PrefixLength,
    int EffectivePrefixLength,
    IReadOnlyList<string> Immediate24Hosts,
    IReadOnlyList<string> SubnetHosts);

public sealed class LocalNetworkEndpoint
{
    public string InterfaceId { get; init; } = string.Empty;
    public string InterfaceName { get; init; } = "LAN";
    public string Description { get; init; } = string.Empty;
    public NetworkInterfaceType InterfaceType { get; init; }
    public string Ipv4Address { get; init; } = "127.0.0.1";
    public string SubnetMask { get; init; } = "255.255.255.0";
    public string BroadcastAddress { get; init; } = "255.255.255.255";
    public bool HasGateway { get; init; }
    public bool IsVirtual { get; init; }
    public bool IsLoopbackFallback { get; init; }

    public string DisplayLabel => IsLoopbackFallback
        ? "127.0.0.1 (Sin red LAN)"
        : $"{Ipv4Address} ({InterfaceName})";

    public override string ToString() => DisplayLabel;
}

/// <summary>
/// Detector inteligente de adaptadores de red reales (Wi-Fi / Ethernet) con cálculo exacto de Broadcast de subred
/// y suscripción en tiempo real a NetworkChange.NetworkAddressChanged.
/// </summary>
public static class NetworkAddressService
{
    private static readonly string[] VirtualAdapterKeywords =
    {
        "vethernet", "wsl", "hyper-v", "docker", "vmware", "virtualbox",
        "vbox", "tailscale", "zerotier", "npcap", "radmin", "hamachi",
        "tap-", "tun-", "loopback", "bluetooth", "teredo", "isatap"
    };

    private static string? _userPreferredIp;
    private static bool _subscribed;

    public static event Action<LocalNetworkEndpoint>? OnNetworkEndpointsChanged;

    public static void InitializeMonitoring()
    {
        if (_subscribed) return;
        _subscribed = true;

        NetworkChange.NetworkAddressChanged += (_, _) =>
        {
            try
            {
                RefreshRuntimePrimaryEndpoint();
            }
            catch { }
        };

        RefreshRuntimePrimaryEndpoint();
    }

    public static List<LocalNetworkEndpoint> GetAvailableIpv4Endpoints()
    {
        var physicalEndpoints = new List<LocalNetworkEndpoint>();
        var virtualEndpoints = new List<LocalNetworkEndpoint>();

        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up)
                    continue;

                if (ni.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                    continue;

                string nameAndDesc = $"{ni.Name} {ni.Description}".ToLowerInvariant();
                bool isVirtual = VirtualAdapterKeywords.Any(k => nameAndDesc.Contains(k, StringComparison.Ordinal));

                IPInterfaceProperties ipProps;
                try
                {
                    ipProps = ni.GetIPProperties();
                }
                catch
                {
                    continue;
                }

                bool hasIpv4Gateway = ipProps.GatewayAddresses.Any(g =>
                    g.Address.AddressFamily == AddressFamily.InterNetwork &&
                    !g.Address.Equals(IPAddress.Any) &&
                    !g.Address.Equals(IPAddress.None));

                foreach (var ua in ipProps.UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != AddressFamily.InterNetwork)
                        continue;

                    if (IPAddress.IsLoopback(ua.Address))
                        continue;

                    byte[] ipBytes = ua.Address.GetAddressBytes();
                    // Ignorar direcciones APIPA 169.254.x.x
                    if (ipBytes[0] == 169 && ipBytes[1] == 254)
                        continue;

                    IPAddress maskAddr = ua.IPv4Mask ?? IPAddress.Parse("255.255.255.0");
                    byte[] maskBytes = maskAddr.GetAddressBytes();
                    if (maskBytes.All(b => b == 0))
                        maskBytes = new byte[] { 255, 255, 255, 0 };

                    byte[] bcastBytes = new byte[4];
                    for (int i = 0; i < 4; i++)
                        bcastBytes[i] = (byte)(ipBytes[i] | (maskBytes[i] ^ 255));

                    var endpoint = new LocalNetworkEndpoint
                    {
                        InterfaceId = ni.Id,
                        InterfaceName = ni.Name,
                        Description = ni.Description,
                        InterfaceType = ni.NetworkInterfaceType,
                        Ipv4Address = ua.Address.ToString(),
                        SubnetMask = new IPAddress(maskBytes).ToString(),
                        BroadcastAddress = new IPAddress(bcastBytes).ToString(),
                        HasGateway = hasIpv4Gateway,
                        IsVirtual = isVirtual,
                        IsLoopbackFallback = false
                    };

                    if (isVirtual)
                        virtualEndpoints.Add(endpoint);
                    else
                        physicalEndpoints.Add(endpoint);
                }
            }
        }
        catch { }

        var orderedPhysical = physicalEndpoints
            .OrderByDescending(e => e.HasGateway)
            .ThenByDescending(e => e.InterfaceType is NetworkInterfaceType.Wireless80211 or NetworkInterfaceType.Ethernet)
            .ThenBy(e => e.InterfaceName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var orderedVirtual = virtualEndpoints
            .OrderByDescending(e => e.HasGateway)
            .ThenBy(e => e.InterfaceName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var result = new List<LocalNetworkEndpoint>();
        result.AddRange(orderedPhysical);
        result.AddRange(orderedVirtual);

        if (result.Count == 0)
        {
            result.Add(new LocalNetworkEndpoint
            {
                InterfaceId = "loopback",
                InterfaceName = "Sin red LAN",
                Description = "Loopback Local",
                InterfaceType = NetworkInterfaceType.Loopback,
                Ipv4Address = "127.0.0.1",
                SubnetMask = "255.0.0.0",
                BroadcastAddress = "255.255.255.255",
                HasGateway = false,
                IsVirtual = true,
                IsLoopbackFallback = true
            });
        }

        return result;
    }

    public static LocalNetworkEndpoint GetPrimaryIpv4()
    {
        var all = GetAvailableIpv4Endpoints();

        if (!string.IsNullOrWhiteSpace(_userPreferredIp))
        {
            var preferred = all.FirstOrDefault(e =>
                string.Equals(e.Ipv4Address, _userPreferredIp, StringComparison.OrdinalIgnoreCase));
            if (preferred != null)
                return preferred;
        }

        // Priorizar interfaz física con Gateway; si no hay, interfaz física sin Gateway; si no hay, la primera disponible
        return all.FirstOrDefault(e => !e.IsVirtual && e.HasGateway)
               ?? all.FirstOrDefault(e => !e.IsVirtual)
               ?? all[0];
    }

    public static LocalNetworkEndpoint SelectActiveEndpoint(string? ipv4Address)
    {
        _userPreferredIp = ipv4Address;
        return RefreshRuntimePrimaryEndpoint();
    }

    public static LocalNetworkEndpoint RefreshRuntimePrimaryEndpoint()
    {
        var primary = GetPrimaryIpv4();
        NodeRuntimeState.UpdateActiveNetworkEndpoint(primary);
        OnNetworkEndpointsChanged?.Invoke(primary);
        return primary;
    }

    /// <summary>
    /// Calcula los hosts escaneables de la subred real usando IPv4 + IPv4Mask.
    /// Si la máscara es mayor a /22 (ej. /20 o /16), acota un bloque /22 (hasta 1,022 IPs cubriendo
    /// los 4 segmentos /24 contiguos alrededor de la IP local), excluyendo dirección de red y broadcast.
    /// </summary>
    public static SubnetScanPlan ComputeSubnetScanPlan(string? localIp, string? subnetMask = null, bool includeLocalIp = false)
    {
        if (!IPAddress.TryParse(localIp, out var ipObj) ||
            ipObj.AddressFamily != AddressFamily.InterNetwork ||
            IPAddress.IsLoopback(ipObj))
        {
            var fallback = new List<string>(254);
            for (int h = 1; h <= 254; h++)
                fallback.Add($"192.168.1.{h}");
            return new SubnetScanPlan("192.168.1.0", "192.168.1.255", 24, 24, fallback, fallback);
        }

        if (!IPAddress.TryParse(subnetMask, out var maskObj) || maskObj.AddressFamily != AddressFamily.InterNetwork)
            maskObj = IPAddress.Parse("255.255.255.0");

        uint ipUint = BinaryPrimitives.ReadUInt32BigEndian(ipObj.GetAddressBytes());
        uint maskUint = BinaryPrimitives.ReadUInt32BigEndian(maskObj.GetAddressBytes());
        if (maskUint == 0)
            maskUint = 0xFFFFFF00u;

        int prefixLen = BitOperations.PopCount(maskUint);
        if (prefixLen >= 31)
        {
            return new SubnetScanPlan(ipObj.ToString(), ipObj.ToString(), prefixLen, prefixLen, Array.Empty<string>(), Array.Empty<string>());
        }

        int effectivePrefix = Math.Max(prefixLen, 22);
        uint effectiveMask = effectivePrefix == 0 ? 0u : (uint.MaxValue << (32 - effectivePrefix));

        uint effNetwork = ipUint & effectiveMask;
        uint effBroadcast = effNetwork | ~effectiveMask;
        uint firstHost = effNetwork + 1;
        uint lastHost = effBroadcast - 1;

        uint immediate24Net = ipUint & 0xFFFFFF00u;
        uint immediate24Bcast = immediate24Net | 0x000000FFu;

        var immediate24 = new List<string>(254);
        for (uint addr = immediate24Net + 1; addr <= immediate24Bcast - 1; addr++)
        {
            if (!includeLocalIp && addr == ipUint) continue;
            if (addr <= effNetwork || addr >= effBroadcast) continue;
            immediate24.Add(UintToIpv4String(addr));
        }

        var allHosts = new List<string>((int)Math.Min(1022, (long)lastHost - firstHost + 1));
        allHosts.AddRange(immediate24);

        for (uint addr = firstHost; addr <= lastHost; addr++)
        {
            if (addr > immediate24Net && addr < immediate24Bcast) continue;
            if (!includeLocalIp && addr == ipUint) continue;
            allHosts.Add(UintToIpv4String(addr));
        }

        return new SubnetScanPlan(
            UintToIpv4String(effNetwork),
            UintToIpv4String(effBroadcast),
            prefixLen,
            effectivePrefix,
            immediate24,
            allHosts);
    }

    private static string UintToIpv4String(uint ipUint)
    {
        Span<byte> buf = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buf, ipUint);
        return $"{buf[0]}.{buf[1]}.{buf[2]}.{buf[3]}";
    }

    private static string ScanHostsFilePath => Path.Combine(AppDbContext.AppDataDirectory, "scan_hosts.json");

    public static List<string> LoadScanHosts()
    {
        try
        {
            if (!File.Exists(ScanHostsFilePath))
                return new List<string>();

            string json = File.ReadAllText(ScanHostsFilePath);
            var parsed = JsonSerializer.Deserialize<List<string>>(json);
            return NormalizeScanHostList(parsed);
        }
        catch
        {
            return new List<string>();
        }
    }

    public static List<string> SaveScanHosts(IEnumerable<string>? hosts)
    {
        var normalized = NormalizeScanHostList(hosts);
        try
        {
            Directory.CreateDirectory(AppDbContext.AppDataDirectory);
            string json = JsonSerializer.Serialize(normalized, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(ScanHostsFilePath, json);
        }
        catch { }
        return normalized;
    }

    public static List<string> ParseScanHostsCsv(string? csv)
    {
        if (string.IsNullOrWhiteSpace(csv))
            return new List<string>();

        var tokens = csv.Split(new[] { ',', ';', '\r', '\n', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        return NormalizeScanHostList(tokens);
    }

    public static List<string> NormalizeScanHostList(IEnumerable<string>? rawHosts)
    {
        var result = new List<string>();
        if (rawHosts == null) return result;

        foreach (string item in rawHosts)
        {
            string trimmed = (item ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(trimmed)) continue;

            // Soporta tanto "10.10.5.20" como "10.10.5.20:5006"
            int colonIdx = trimmed.IndexOf(':');
            if (colonIdx > 0)
            {
                string ipPart = trimmed[..colonIdx].Trim();
                string portPart = trimmed[(colonIdx + 1)..].Trim();
                if (IPAddress.TryParse(ipPart, out var parsedIp) &&
                    parsedIp.AddressFamily == AddressFamily.InterNetwork &&
                    int.TryParse(portPart, out int p) && p is > 0 and <= 65535)
                {
                    string entry = $"{parsedIp}:{p}";
                    if (!result.Contains(entry, StringComparer.OrdinalIgnoreCase))
                        result.Add(entry);
                }
            }
            else if (IPAddress.TryParse(trimmed, out var ipOnly) && ipOnly.AddressFamily == AddressFamily.InterNetwork)
            {
                string entry = ipOnly.ToString();
                if (!result.Contains(entry, StringComparer.OrdinalIgnoreCase))
                    result.Add(entry);
            }
        }
        return result;
    }
}
