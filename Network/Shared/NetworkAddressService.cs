using ModuloCrypto.Core.Services;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace ModuloCrypto.Network.Shared;

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
}
