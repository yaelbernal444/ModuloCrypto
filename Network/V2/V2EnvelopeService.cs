using ModuloCrypto.Core.Contracts;
using ModuloCrypto.Core.Services;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ModuloCrypto.Network.V2;

/// <summary>
/// Implementación del Sobre Híbrido CC-ENV-1 del Estándar v2.0 (Sección 5.3):
/// - CEK aleatoria de 32 bytes + nonce de 12 bytes + AES-256-GCM (tag 16 bytes, AAD = UTF-8(requestId o packetId))
/// - CEK envuelta con RSA-OAEP-SHA256 (MGF1-SHA256, sin etiqueta) usando el certificado del destinatario
/// - Validación de recipientThumbprintSha256 en tiempo constante (401 E-ENV-RECIPIENT / 400 E-ENV-DECRYPT)
/// - Limpieza obligatoria de CEK y secretos en memoria con CryptographicOperations.ZeroMemory en finally.
/// </summary>
public static class V2EnvelopeService
{
    public static CcHybridEnvelope Seal(
        byte[] plaintextSecret,
        X509Certificate2 recipientCert,
        string recipientNodeId,
        string aadContext)
    {
        ArgumentNullException.ThrowIfNull(plaintextSecret);
        ArgumentNullException.ThrowIfNull(recipientCert);

        using RSA? recipientRsa = recipientCert.GetRSAPublicKey();
        if (recipientRsa == null || recipientRsa.KeySize < 2048)
            throw new PacketValidationException("E-CERT", 400, "El certificado del destinatario no contiene llave pública RSA >= 2048 bits.");

        byte[] cek = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ciphertext = new byte[plaintextSecret.Length];
        byte[] tag = new byte[16];
        byte[] aadBytes = Encoding.UTF8.GetBytes(aadContext ?? string.Empty);

        try
        {
            using (var aesGcm = new AesGcm(cek, 16))
            {
                aesGcm.Encrypt(nonce, plaintextSecret, ciphertext, tag, aadBytes);
            }

            byte[] wrappedCek = recipientRsa.Encrypt(cek, RSAEncryptionPadding.OaepSHA256);
            string recipientThumb = V2CertificateService.GetThumbprintSha256Hex(recipientCert);

            return new CcHybridEnvelope
            {
                Version = "CC-ENV-1",
                RecipientNode = string.IsNullOrWhiteSpace(recipientNodeId) ? "EQ01" : recipientNodeId.ToUpperInvariant(),
                RecipientThumbprintSha256 = recipientThumb,
                KeyWrapAlgorithm = "RSA-OAEP-SHA256",
                ContentEncryptionAlgorithm = "AES-256-GCM",
                AadContext = aadContext ?? string.Empty,
                EncryptedKeyBase64 = Convert.ToBase64String(wrappedCek),
                NonceBase64 = Convert.ToBase64String(nonce),
                CiphertextBase64 = Convert.ToBase64String(ciphertext),
                TagBase64 = Convert.ToBase64String(tag)
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cek);
        }
    }

    public static byte[] Open(
        CcHybridEnvelope envelope,
        string expectedAadContext,
        X509Certificate2? recipientCertWithPrivateKey = null)
    {
        if (envelope == null || !string.Equals(envelope.Version, "CC-ENV-1", StringComparison.Ordinal))
            throw new PacketValidationException("E-ENV-DECRYPT", 400, "El sobre híbrido no es válido o su versión no es CC-ENV-1.");

        var ownCert = recipientCertWithPrivateKey ?? V2CertificateService.CurrentCertificate;
        string ownThumb = V2CertificateService.GetThumbprintSha256Hex(ownCert);

        // Validar recipientThumbprintSha256 en tiempo constante -> 401 E-ENV-RECIPIENT
        if (!V2CertificateService.FixedTimeEqualsHex(ownThumb, envelope.RecipientThumbprintSha256))
        {
            throw new PacketValidationException(
                "E-ENV-RECIPIENT",
                401,
                $"El sobre CC-ENV-1 está dirigido a la huella '{envelope.RecipientThumbprintSha256}', que no coincide con la huella activa de {NodeRuntimeState.CurrentNodeId} ('{ownThumb}').");
        }

        using RSA? privateRsa = ownCert.GetRSAPrivateKey();
        if (privateRsa == null)
            throw new PacketValidationException("E-ENV-DECRYPT", 400, "El certificado activo no posee llave privada para abrir CC-ENV-1.");

        byte[]? cek = null;
        try
        {
            byte[] wrappedKey = Convert.FromBase64String(envelope.EncryptedKeyBase64);
            byte[] nonce = Convert.FromBase64String(envelope.NonceBase64);
            byte[] ciphertext = Convert.FromBase64String(envelope.CiphertextBase64);
            byte[] tag = Convert.FromBase64String(envelope.TagBase64);

            cek = privateRsa.Decrypt(wrappedKey, RSAEncryptionPadding.OaepSHA256);
            if (cek.Length != 32)
                throw new CryptographicException("La CEK desenvuelta no tiene 32 bytes.");

            string aad = !string.IsNullOrEmpty(expectedAadContext) ? expectedAadContext : envelope.AadContext;
            byte[] aadBytes = Encoding.UTF8.GetBytes(aad ?? string.Empty);

            byte[] plaintext = new byte[ciphertext.Length];
            using var aesGcm = new AesGcm(cek, 16);
            aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, aadBytes);
            return plaintext;
        }
        catch (PacketValidationException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new PacketValidationException("E-ENV-DECRYPT", 400, $"Fallo al desenvolver o autenticar sobre CC-ENV-1: {ex.Message}");
        }
        finally
        {
            if (cek != null)
                CryptographicOperations.ZeroMemory(cek);
        }
    }
}
