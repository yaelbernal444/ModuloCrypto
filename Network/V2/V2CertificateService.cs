using ModuloCrypto.Core.Services;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace ModuloCrypto.Network.V2;

/// <summary>
/// Administra el certificado X.509 RSA-2048 de la Versión 2.0 (node_identity_v2.pfx protegido con DPAPI):
/// - Sujeto exacto: CN=EQ01, OU=Equipo 01, O=Centro de Ciberseguridad, C=MX
/// - Vigencia: 365 días
/// - Serial aleatorio >= 64 bits
/// - Usos: DigitalSignature | KeyEncipherment
/// - Huella SHA-256 en HEX MAYÚSCULAS (64 caracteres ^[0-9A-F]{64}$)
/// - Firma exclusiva: RSA-PSS con SHA-256 (MGF1-SHA256, sal 32 bytes). Sin fallback a PKCS#1.
/// </summary>
public static class V2CertificateService
{
    private static readonly byte[] DpapiEntropy = Encoding.UTF8.GetBytes("ModuloCrypto.X509.DPAPI.v2");
    private static X509Certificate2? _currentCert;

    private static string CertFileSuffix => NodeRuntimeState.TeamNumber == 1
        ? "v2"
        : $"v2_EQ{NodeRuntimeState.TeamNumber:D2}";

    private static string CertPath => Path.Combine(AppContext.BaseDirectory, $"node_identity_{CertFileSuffix}.pfx");
    private static string KeyPath => Path.Combine(AppContext.BaseDirectory, $"node_identity_{CertFileSuffix}.key");

    public static X509Certificate2 CurrentCertificate => _currentCert ?? Initialize();

    public static string Subject => CurrentCertificate.Subject;
    public static string Thumbprint => GetThumbprintSha256Hex();

    public static string ExpectedNodeId => NodeRuntimeState.IsValidNodeId(NodeRuntimeState.CurrentNodeId)
        ? NodeRuntimeState.CurrentNodeId
        : $"EQ{NodeRuntimeState.TeamNumber:D2}";

    public static string ExpectedSubjectDistinguishedName =>
        $"CN={ExpectedNodeId}, OU=Equipo {NodeRuntimeState.TeamNumber:D2}, O=Centro de Ciberseguridad, C=MX";

    public static X509Certificate2 Initialize(bool forceRegenerate = false)
    {
        string expectedCn = $"CN={ExpectedNodeId}";
        string expectedOu = $"OU=Equipo {NodeRuntimeState.TeamNumber:D2}";
        const string expectedOrg = "O=Centro de Ciberseguridad";

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
                        loaded.Subject.Contains(expectedOu, StringComparison.OrdinalIgnoreCase) &&
                        loaded.Subject.Contains(expectedOrg, StringComparison.OrdinalIgnoreCase) &&
                        loaded.NotAfter.ToUniversalTime() > DateTime.UtcNow)
                    {
                        _currentCert = loaded;
                        NodeRuntimeState.CertificateActive = true;
                        SyncSelfPeerThumbprint(_currentCert);
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
            var subjectDn = new X500DistinguishedName(ExpectedSubjectDistinguishedName);
            var req = new CertificateRequest(
                subjectDn,
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(365);

            // Serial aleatorio de 16 bytes (128 bits >= 64 bits), positivo
            byte[] serialNumber = RandomNumberGenerator.GetBytes(16);
            serialNumber[0] &= 0x7F;
            if (serialNumber[0] == 0) serialNumber[0] = 0x01;

            var sigGenerator = X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1);
            using var pubCert = req.Create(subjectDn, sigGenerator, notBefore, notAfter, serialNumber);
            using var createdWithKey = pubCert.CopyWithPrivateKey(rsa);

            byte[] pfxBytes = createdWithKey.Export(X509ContentType.Pfx, secretPass);
            try
            {
                File.WriteAllBytes(CertPath, pfxBytes);
                _currentCert?.Dispose();
                _currentCert = X509CertificateLoader.LoadPkcs12(pfxBytes, secretPass, X509KeyStorageFlags.Exportable);
                NodeRuntimeState.CertificateActive = true;
                SyncSelfPeerThumbprint(_currentCert);
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

    private static void SyncSelfPeerThumbprint(X509Certificate2 cert)
    {
        try
        {
            string thumb = GetThumbprintSha256Hex(cert);
            string pem = cert.ExportCertificatePem();
            string selfId = ExpectedNodeId;

            var selfPeer = NodeRuntimeState.NetworkPeers.FirstOrDefault(p =>
                string.Equals(p.NodeId, selfId, StringComparison.OrdinalIgnoreCase));
            if (selfPeer != null)
            {
                selfPeer.CertThumbprint = thumb;
                selfPeer.PinnedThumbprintSha256 = thumb;
                selfPeer.CertificatePem = pem;
                selfPeer.IsConfirmed = true;
                selfPeer.HasThumbprintMismatch = false;
                selfPeer.Status = "online";
                ModuloCrypto.Core.Data.AppDbContext.UpsertTrustedPeer(selfPeer);
            }
        }
        catch { }
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

    public static string GetThumbprintSha256Hex(X509Certificate2 cert)
    {
        return Convert.ToHexString(cert.GetCertHash(HashAlgorithmName.SHA256)).ToUpperInvariant();
    }

    /// <summary>
    /// Firma exclusivamente con RSA-PSS-SHA256 (MGF1-SHA256, sal 32 bytes).
    /// </summary>
    public static string SignDataPss(byte[] data)
    {
        using RSA? rsa = CurrentCertificate.GetRSAPrivateKey();
        if (rsa == null)
            throw new InvalidOperationException("El certificado X.509 v2.0 del nodo no contiene clave privada RSA.");

        byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        return Convert.ToBase64String(signature);
    }

    /// <summary>
    /// Verifica firma exclusivamente con RSA-PSS-SHA256 (sin fallback a PKCS#1).
    /// </summary>
    public static bool VerifyWithPem(byte[] data, string signatureBase64, string certPemOrBase64)
    {
        if (data == null || string.IsNullOrWhiteSpace(signatureBase64) || string.IsNullOrWhiteSpace(certPemOrBase64))
            return false;

        try
        {
            byte[] sigBytes = Convert.FromBase64String(signatureBase64.Trim());
            if (sigBytes.Length != 256)
                return false;

            using X509Certificate2 cert = LoadCertificateFromPemOrBase64(certPemOrBase64);
            using RSA? rsa = cert.GetRSAPublicKey();
            if (rsa == null || rsa.KeySize != 2048)
                return false;

            return rsa.VerifyData(data, sigBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }
        catch
        {
            return false;
        }
    }

    public static bool ValidateCertificateMetadata(
        X509Certificate2 cert,
        string expectedNodeId,
        out string errorDetail)
    {
        errorDetail = string.Empty;

        if (!NodeRuntimeState.IsValidNodeId(expectedNodeId))
        {
            errorDetail = $"NodeId '{expectedNodeId}' no cumple formato ^EQ[0-9]{{2}}$.";
            return false;
        }

        DateTime nowUtc = DateTime.UtcNow;
        if (nowUtc < cert.NotBefore.ToUniversalTime().AddMinutes(-5) ||
            nowUtc > cert.NotAfter.ToUniversalTime().AddMinutes(5))
        {
            errorDetail = "El certificado X.509 está fuera de su periodo de vigencia.";
            return false;
        }

        using RSA? rsa = cert.GetRSAPublicKey();
        if (rsa == null || rsa.KeySize < 2048)
        {
            errorDetail = "El certificado X.509 debe poseer llave pública RSA >= 2048 bits.";
            return false;
        }

        string cnPattern = $@"\bCN\s*=\s*{Regex.Escape(expectedNodeId)}\b";
        if (!Regex.IsMatch(cert.Subject, cnPattern, RegexOptions.IgnoreCase))
        {
            errorDetail = $"El CN del certificado ('{cert.Subject}') no coincide con '{expectedNodeId}'.";
            return false;
        }

        return true;
    }

    public static bool FixedTimeEqualsHex(string hexA, string hexB)
    {
        if (string.IsNullOrWhiteSpace(hexA) || string.IsNullOrWhiteSpace(hexB))
            return false;

        byte[] a = Encoding.ASCII.GetBytes(hexA.Trim().ToUpperInvariant());
        byte[] b = Encoding.ASCII.GetBytes(hexB.Trim().ToUpperInvariant());
        return CryptographicOperations.FixedTimeEquals(a, b);
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
