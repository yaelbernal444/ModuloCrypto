using ModuloCrypto.Core.Services;
using ModuloCrypto.Network.Shared;
using System.Security.Cryptography.X509Certificates;

namespace ModuloCrypto.Network.V1;

/// <summary>
/// Runtime de ciclo de vida para la Versión 1.0 (NODO-01, puerto 5000, node_identity_v1.pfx).
/// </summary>
public sealed class V1ProtocolRuntime : INodeProtocolRuntime
{
    private readonly V1ApiHostService _apiHost = new();

    public ProtocolVersionMode Version => ProtocolVersionMode.V1;
    public string VersionNumber => "1.0";
    public string VersionBadgeText => $"PROTO v1.0 ({NodeId})";
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
            V1CertificateService.Initialize();
        }
        catch
        {
            NodeRuntimeState.CertificateActive = false;
        }

        return await _apiHost.StartAsync(port);
    }

    public async Task StopAsync()
    {
        await _apiHost.DisposeAsync();
    }

    public string GetCertificateSubject() => V1CertificateService.Subject;

    public string GetCertificateThumbprint() => V1CertificateService.GetThumbprintSha256Hex();

    public string GetCertificateDetailsReport(string operatorFullName, string operatorUsername)
    {
        var cert = V1CertificateService.CurrentCertificate;
        return
            $"Versión Protocolo  : v1.0 — Legado ModuloCrypto\r\n" +
            $"Nodo Activo        : {NodeRuntimeState.CurrentNodeId}\r\n" +
            $"Algoritmos Locales : 21 algoritmos oficiales completos\r\n" +
            $"Operador Logueado  : {operatorFullName} ({operatorUsername})\r\n" +
            $"API v1.0 Embebida  : http://0.0.0.0:{NodeRuntimeState.ApiPort}\r\n" +
            $"Empaquetado .ZIP   : Híbrido 5 archivos (manifest, datos.enc, payload.bin, pem, cer)\r\n" +
            $"---------------------------------------------------\r\n" +
            $"Archivo PFX (DPAPI): node_identity_v1.pfx\r\n" +
            $"X.509 Subject      : {cert.Subject}\r\n" +
            $"X.509 SHA-256 (64) : {V1CertificateService.GetThumbprintSha256Hex()}\r\n" +
            $"Serial             : {cert.SerialNumber}\r\n" +
            $"Firma              : Dual (RSA-PSS-SHA256 + PKCS#1 v1.5)\r\n" +
            $"Vigencia           : {cert.NotBefore.ToUniversalTime():yyyy-MM-dd} a {cert.NotAfter.ToUniversalTime():yyyy-MM-dd} UTC";
    }

    public X509Certificate2 RegenerateCertificate() => V1CertificateService.Initialize(forceRegenerate: true);

    public Task AnnouncePresenceAsync() => Task.CompletedTask;

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
    }
}
