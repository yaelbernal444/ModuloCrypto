using ModuloCrypto.Core.Services;
using ModuloCrypto.Network.Shared;
using System.Security.Cryptography.X509Certificates;

namespace ModuloCrypto.Network.V2;

/// <summary>
/// Runtime de ciclo de vida para la Versión 2.0 (EQ01..EQ08, puerto 5000+Team, UDP 5099, node_identity_v2.pfx).
/// </summary>
public sealed class V2ProtocolRuntime : INodeProtocolRuntime
{
    private readonly V2ApiHostService _apiHost = new();
    private readonly V2UdpDiscoveryService _udpDiscovery = new();

    public ProtocolVersionMode Version => ProtocolVersionMode.V2;
    public string VersionNumber => "2.0";
    public string VersionBadgeText => $"PROTO v2.0 ({NodeId})";
    public string NodeId => NodeRuntimeState.CurrentNodeId;
    public int HttpPort => NodeRuntimeState.ApiPort;
    public bool IsApiOnline => NodeRuntimeState.ApiOnline;
    public string LastStartupError => _apiHost.LastStartupError;

    public async Task<bool> StartAsync(int port)
    {
        try
        {
            ModuloCrypto.Core.Data.AppDbContext.InitializeDatabase();
        }
        catch { }

        try
        {
            V2CertificateService.Initialize();
        }
        catch
        {
            NodeRuntimeState.CertificateActive = false;
        }

        bool apiOk = await _apiHost.StartAsync(port);
        _udpDiscovery.Start();
        return apiOk;
    }

    public async Task StopAsync()
    {
        await _udpDiscovery.DisposeAsync();
        await _apiHost.DisposeAsync();
    }

    public string GetCertificateSubject() => V2CertificateService.Subject;

    public string GetCertificateThumbprint() => V2CertificateService.GetThumbprintSha256Hex();

    public string GetCertificateDetailsReport(string operatorFullName, string operatorUsername)
    {
        var cert = V2CertificateService.CurrentCertificate;
        return
            $"Versión Protocolo  : v2.0 — Estándar Interoperable\r\n" +
            $"Nodo Activo        : {NodeRuntimeState.CurrentNodeId} (Equipo {NodeRuntimeState.TeamNumber:D2})\r\n" +
            $"Algoritmos Dueño   : {string.Join(", ", NodeRuntimeState.OwnedAlgorithms)}\r\n" +
            $"Operador Logueado  : {operatorFullName} ({operatorUsername})\r\n" +
            $"API v2.0 Embebida  : http://0.0.0.0:{NodeRuntimeState.ApiPort}\r\n" +
            $"Beacon UDP 5099    : Activo (CC-BEACON cada 30s + Broadcast {NodeRuntimeState.SubnetBroadcastAddress})\r\n" +
            $"Sobre Híbrido      : CC-ENV-1 (RSA-OAEP-SHA256 + AES-256-GCM)\r\n" +
            $"---------------------------------------------------\r\n" +
            $"X.509 Subject      : {cert.Subject}\r\n" +
            $"X.509 SHA-256 (64) : {V2CertificateService.GetThumbprintSha256Hex()}\r\n" +
            $"Serial (>=64 bits) : {cert.SerialNumber}\r\n" +
            $"Firma Estándar     : RSA-PSS-SHA256 (MGF1, sal 32B)\r\n" +
            $"Vigencia (365 días): {cert.NotBefore.ToUniversalTime():yyyy-MM-dd} a {cert.NotAfter.ToUniversalTime():yyyy-MM-dd} UTC";
    }

    public X509Certificate2 RegenerateCertificate() => V2CertificateService.Initialize(forceRegenerate: true);

    public async Task AnnouncePresenceAsync()
    {
        await _udpDiscovery.SendBeaconAsync("online");
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
    }
}
