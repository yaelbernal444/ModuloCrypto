using ModuloCrypto.Core.Services;
using System.Security.Cryptography.X509Certificates;

namespace ModuloCrypto.Network.Shared;

/// <summary>
/// Interfaz común para que Program.cs y FormDashboard operen con la versión elegida en el Login
/// (Versión 1.0 Legado NODO-01 o Versión 2.0 Estándar Interoperable EQ01) sin condicionales caóticos.
/// </summary>
public interface INodeProtocolRuntime : IAsyncDisposable
{
    ProtocolVersionMode Version { get; }
    string VersionNumber { get; }
    string VersionBadgeText { get; }
    string NodeId { get; }
    int HttpPort { get; }
    bool IsApiOnline { get; }
    string LastStartupError { get; }

    Task<bool> StartAsync(int port);
    Task StopAsync();

    string GetCertificateSubject();
    string GetCertificateThumbprint();
    string GetCertificateDetailsReport(string operatorFullName, string operatorUsername);
    X509Certificate2 RegenerateCertificate();
    Task AnnouncePresenceAsync();
}
