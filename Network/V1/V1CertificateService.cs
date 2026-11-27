using ModuloCrypto.Core.Services;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ModuloCrypto.Network.V1;

/// <summary>
/// Administra el certificado X.509 RSA-2048 de la Versión 1.0 (node_identity_v1.pfx, protegido con Windows DPAPI)
/// con soporte dual de firma y verificación (RSA-PSS y PKCS#1 v1.5).
/// </summary>
public static class V1CertificateService
{
    private static readonly byte[] DpapiEntropy = Encoding.UTF8.GetBytes("ModuloCrypto.X509.DPAPI.v1");
    private static X509Certificate2? _currentCert;

    private static string CertPath => Path.Combine(Core.Data.AppDbContext.AppDataDirectory, "node_identity_v1.pfx");
    private static string KeyPath => Path.Combine(Core.Data.AppDbContext.AppDataDirectory, "node_identity_v1.key");

    public static X509Certificate2 CurrentCertificate => _currentCert ?? Initialize();

    public static string Subject => CurrentCertificate.Subject;
    public static string Thumbprint => GetThumbprintSha256Hex();

    public static X509Certificate2 Initialize(bool forceRegenerate = false)
    {
        string expectedCn = $"CN={NodeRuntimeState.CurrentNodeId}";

        byte[] secretBytes = GetOrCreateDpapiProtectedSecretBytes(forceRegenerate);
        string secretPass = Convert.ToBase64String(secretBytes);

        try
        {
            if (!forceRegenerate && File.Exists(CertPath))
            {
                try
                {
                    _currentCert?.Dispose();
                    var loaded = X509CertificateLoader.LoadPkcs12FromFile(
                        CertPath,
                        secretPass,
                        X509KeyStorageFlags.Exportable);

                    if (loaded.Subject.Contains(expectedCn, StringComparison.OrdinalIgnoreCase) &&
                        loaded.NotAfter.ToUniversalTime() > DateTime.UtcNow)
                    {
                        _currentCert = loaded;
                        NodeRuntimeState.CertificateActive = true;
                        return _currentCert;
                    }
                    loaded.Dispose();
                }
                catch
                {
                    CryptographicOperations.ZeroMemory(secretBytes);
                    secretBytes = GetOrCreateDpapiProtectedSecretBytes(forceNew: true);
                    secretPass = Convert.ToBase64String(secretBytes);
                }
            }

            using var rsa = RSA.Create(2048);
            var subjectDn = new X500DistinguishedName($"CN={NodeRuntimeState.CurrentNodeId}, OU=RedTor8Nodos, O=ModuloCrypto, C=MX");
            var req = new CertificateRequest(
                subjectDn,
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

            using var created = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(3));

            byte[] pfxBytes = created.Export(X509ContentType.Pfx, secretPass);
            try
            {
                File.WriteAllBytes(CertPath, pfxBytes);
                _currentCert?.Dispose();
                _currentCert = X509CertificateLoader.LoadPkcs12(pfxBytes, secretPass, X509KeyStorageFlags.Exportable);
                NodeRuntimeState.CertificateActive = true;
                return _currentCert;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pfxBytes);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secretBytes);
        }
    }

    private static byte[] GetOrCreateDpapiProtectedSecretBytes(bool forceNew)
    {
        if (!forceNew && File.Exists(KeyPath))
        {
            try
            {
                byte[] encrypted = File.ReadAllBytes(KeyPath);
                return ProtectedData.Unprotect(encrypted, DpapiEntropy, DataProtectionScope.CurrentUser);
            }
            catch { }
        }

        byte[] randomSecret = RandomNumberGenerator.GetBytes(32);
        byte[] protectedBytes = ProtectedData.Protect(randomSecret, DpapiEntropy, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(KeyPath, protectedBytes);
        return randomSecret;
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
        return Convert.ToHexString(CurrentCertificate.GetCertHash(HashAlgorithmName.SHA256)).ToUpperInvariant();
    }

    public static string SignPayload(byte[] payload)
    {
        using RSA? rsa = CurrentCertificate.GetRSAPrivateKey();
        if (rsa == null) return string.Empty;

        byte[] signature = rsa.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return Convert.ToBase64String(signature);
    }

    public static string SignDataPss(byte[] data)
    {
        using RSA? rsa = CurrentCertificate.GetRSAPrivateKey();
        if (rsa == null) return string.Empty;

        byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        return Convert.ToBase64String(signature);
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
