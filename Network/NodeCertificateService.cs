using ModuloCrypto.Core.Services;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ModuloCrypto.Network;

/// <summary>
/// Administra el certificado X.509 local del nodo para firma raíz y verificación de paquetes Tor (.zip).
/// </summary>
public static class NodeCertificateService
{
    private static readonly string CertPath = Path.Combine(AppContext.BaseDirectory, "node_identity.pfx");
    private const string CertPassword = "ModuloCrypto-X509-NodeKey";
    private static X509Certificate2? _currentCert;

    public static X509Certificate2 CurrentCertificate => _currentCert ?? Initialize();

    public static string Subject => CurrentCertificate.Subject;
    public static string Thumbprint => CurrentCertificate.Thumbprint;

    public static X509Certificate2 Initialize(bool forceRegenerate = false)
    {
        if (!forceRegenerate && File.Exists(CertPath))
        {
            try
            {
                _currentCert?.Dispose();
                _currentCert = X509CertificateLoader.LoadPkcs12FromFile(
                    CertPath,
                    CertPassword,
                    X509KeyStorageFlags.Exportable);
                NodeRuntimeState.CertificateActive = true;
                return _currentCert;
            }
            catch
            {
                // Regenerar si el archivo está corrupto
            }
        }

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            $"CN={NodeRuntimeState.CurrentNodeId}, O=ModuloCrypto-TorMesh, OU=CyberSec-8Nodes",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));

        using var created = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
        byte[] pfxBytes = created.Export(X509ContentType.Pfx, CertPassword);
        File.WriteAllBytes(CertPath, pfxBytes);

        _currentCert?.Dispose();
        _currentCert = X509CertificateLoader.LoadPkcs12(pfxBytes, CertPassword, X509KeyStorageFlags.Exportable);
        NodeRuntimeState.CertificateActive = true;
        return _currentCert;
    }

    public static string ExportPublicCertBase64()
    {
        return Convert.ToBase64String(CurrentCertificate.Export(X509ContentType.Cert));
    }

    public static string SignPayload(byte[] payload)
    {
        using RSA? rsa = CurrentCertificate.GetRSAPrivateKey();
        if (rsa == null)
            throw new InvalidOperationException("El certificado X.509 del nodo no contiene clave privada RSA.");

        byte[] signature = rsa.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return Convert.ToBase64String(signature);
    }

    public static bool VerifyPayloadSignature(byte[] payload, string signatureBase64, string publicCertBase64)
    {
        if (string.IsNullOrWhiteSpace(signatureBase64) || string.IsNullOrWhiteSpace(publicCertBase64))
            return false;

        try
        {
            byte[] certBytes = Convert.FromBase64String(publicCertBase64);
            byte[] sigBytes = Convert.FromBase64String(signatureBase64);
            using var cert = X509CertificateLoader.LoadCertificate(certBytes);
            using RSA? rsa = cert.GetRSAPublicKey();
            if (rsa == null) return false;
            return rsa.VerifyData(payload, sigBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch
        {
            return false;
        }
    }
}
