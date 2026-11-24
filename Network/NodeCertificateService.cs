using ModuloCrypto.Core.Services;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ModuloCrypto.Network;

/// <summary>
/// Administra el certificado X.509 local del nodo (NODO-01) para firma raíz y verificación dual (PEM/DER y RSA-PSS/PKCS#1).
/// </summary>
public static class NodeCertificateService
{
    private static readonly string CertPath = Path.Combine(AppContext.BaseDirectory, "node_identity.pfx");
    private const string CertPassword = "ModuloCrypto-X509-NodeKey";
    private static X509Certificate2? _currentCert;

    public static X509Certificate2 CurrentCertificate => _currentCert ?? Initialize();

    public static string Subject => CurrentCertificate.Subject;
    public static string Thumbprint => GetThumbprintSha256Hex();

    public static X509Certificate2 Initialize(bool forceRegenerate = false)
    {
        string expectedCn = $"CN={NodeRuntimeState.CurrentNodeId}";

        if (!forceRegenerate && File.Exists(CertPath))
        {
            try
            {
                _currentCert?.Dispose();
                var loaded = X509CertificateLoader.LoadPkcs12FromFile(
                    CertPath,
                    CertPassword,
                    X509KeyStorageFlags.Exportable);

                if (loaded.Subject.Contains(expectedCn, StringComparison.OrdinalIgnoreCase))
                {
                    _currentCert = loaded;
                    NodeRuntimeState.CertificateActive = true;
                    return _currentCert;
                }
                loaded.Dispose();
            }
            catch
            {
                // Regenerar si el archivo está corrupto o pertenecía a otro nodo
            }
        }

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            $"{expectedCn}, O=ModuloCrypto-TorMesh, OU=CyberSec-8Nodes",
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

    public static string ExportPublicCertPem()
    {
        return CurrentCertificate.ExportCertificatePem();
    }

    public static string GetThumbprintSha256Hex()
    {
        return Convert.ToHexString(CurrentCertificate.GetCertHash(HashAlgorithmName.SHA256));
    }

    public static string SignDataPss(byte[] data)
    {
        using RSA? rsa = CurrentCertificate.GetRSAPrivateKey();
        if (rsa == null)
            throw new InvalidOperationException("El certificado X.509 del nodo no contiene clave privada RSA.");

        byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        return Convert.ToBase64String(signature);
    }

    public static string SignPayload(byte[] payload)
    {
        return SignDataPss(payload);
    }

    public static bool VerifyPayloadSignature(byte[] payload, string signatureBase64, string publicCertPemOrBase64)
    {
        return VerifyWithPem(payload, signatureBase64, publicCertPemOrBase64);
    }

    public static bool VerifyWithPem(byte[] data, string signatureBase64, string certPemOrBase64)
    {
        if (data == null || string.IsNullOrWhiteSpace(signatureBase64) || string.IsNullOrWhiteSpace(certPemOrBase64))
            return false;

        try
        {
            byte[] sigBytes = Convert.FromBase64String(signatureBase64.Trim());
            using X509Certificate2 cert = LoadCertificateFromPemOrBase64(certPemOrBase64);
            using RSA? rsa = cert.GetRSAPublicKey();
            if (rsa == null) return false;

            if (rsa.VerifyData(data, sigBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
                return true;

            return rsa.VerifyData(data, sigBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch
        {
            return false;
        }
    }

    public static X509Certificate2 LoadCertificateFromPemOrBase64(string certPemOrBase64)
    {
        string trimmed = certPemOrBase64.Trim();
        if (trimmed.Contains("-----BEGIN CERTIFICATE-----", StringComparison.OrdinalIgnoreCase))
        {
            return X509Certificate2.CreateFromPem(trimmed);
        }

        byte[] raw = Convert.FromBase64String(trimmed);
        return X509CertificateLoader.LoadCertificate(raw);
    }
}
