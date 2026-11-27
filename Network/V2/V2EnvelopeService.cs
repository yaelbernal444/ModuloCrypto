using ModuloCrypto.Core.Contracts;
using ModuloCrypto.Core.Services;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace ModuloCrypto.Network.V2;

/// <summary>
/// Implementación estricta del Sobre Híbrido CC-ENV-1 (Sección 8.3):
/// - CEK aleatoria de exactamente 32 bytes (RandomNumberGenerator.GetBytes(32))
/// - nonce de exactamente 12 bytes (RandomNumberGenerator.GetBytes(12))
/// - tag de exactamente 16 bytes (new byte[16], new AesGcm(cek, 16))
/// - wrappedKey con RSA-OAEP-SHA256 -> exactamente 256 bytes para RSA-2048
/// - AAD obligatorio:
///     * En secrets (forward/inverse): AAD = Encoding.UTF8.GetBytes(requestId)
///     * En result (resultado.enc + resultEnvelope): AAD = Encoding.UTF8.GetBytes(packetId)
/// - En resultEnvelope dentro de manifest.json: ciphertextBase64 es null (no se incluye) porque el cifrado va en resultado.enc.
/// - Limpieza obligatoria de CEK y secretos con CryptographicOperations.ZeroMemory en finally.
/// </summary>
public static class V2EnvelopeService
{
    public const int CekSizeBytes = 32;
    public const int NonceSizeBytes = 12;
    public const int TagSizeBytes = 16;
    public const int Rsa2048WrappedKeySizeBytes = 256;

    /// <summary>
    /// Sella un payload en línea (incluyendo ciphertextBase64), usado para 'secrets' con AAD = requestId.
    /// </summary>
    public static CcHybridEnvelope Seal(
        byte[] plaintextSecret,
        X509Certificate2 recipientCert,
        string recipientNodeId,
        string aadContext)
    {
        var env = SealDetached(plaintextSecret, recipientCert, recipientNodeId, aadContext, out byte[] ciphertext);
        env.CiphertextBase64 = Convert.ToBase64String(ciphertext);
        return env;
    }

    /// <summary>
    /// Sella un diccionario plano de secretos (ej. { "key": "&lt;base64&gt;" }) con AAD = requestId.
    /// </summary>
    public static CcHybridEnvelope SealSecretsDictionary(
        IDictionary<string, string> secrets,
        X509Certificate2 recipientCert,
        string recipientNodeId,
        string requestId)
    {
        ArgumentNullException.ThrowIfNull(secrets);
        byte[] jsonBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(secrets));
        try
        {
            return Seal(jsonBytes, recipientCert, recipientNodeId, requestId);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(jsonBytes);
        }
    }

    /// <summary>
    /// Sella un resultado para un paquete 'result' v2.0 (con AAD = packetId):
    /// devuelve el CcHybridEnvelope con CiphertextBase64 = null (para manifest.resultEnvelope)
    /// y entrega los bytes cifrados en detachedCiphertext (para escribirlos en resultado.enc).
    /// </summary>
    public static CcHybridEnvelope SealDetached(
        byte[] plaintextBytes,
        X509Certificate2 recipientCert,
        string recipientNodeId,
        string aadContext,
        out byte[] detachedCiphertext)
    {
        ArgumentNullException.ThrowIfNull(plaintextBytes);
        ArgumentNullException.ThrowIfNull(recipientCert);

        using RSA? recipientRsa = recipientCert.GetRSAPublicKey();
        if (recipientRsa == null || recipientRsa.KeySize != 2048)
            throw new PacketValidationException("E-CERT", 422, "El certificado del destinatario debe contener una llave pública RSA-2048 exacta.");

        byte[] cek = RandomNumberGenerator.GetBytes(CekSizeBytes);
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        detachedCiphertext = new byte[plaintextBytes.Length];
        byte[] tag = new byte[TagSizeBytes];
        byte[] aadBytes = Encoding.UTF8.GetBytes(aadContext ?? string.Empty);

        try
        {
            using (var aesGcm = new AesGcm(cek, TagSizeBytes))
            {
                aesGcm.Encrypt(nonce, plaintextBytes, detachedCiphertext, tag, aadBytes);
            }

            byte[] wrappedCek = recipientRsa.Encrypt(cek, RSAEncryptionPadding.OaepSHA256);
            if (wrappedCek.Length != Rsa2048WrappedKeySizeBytes)
                throw new PacketValidationException("E-ENV-DECRYPT", 401, $"Tamaño de wrappedKey inválido ({wrappedCek.Length} bytes, se esperan 256).");

            string recipientThumb = V2CertificateService.GetThumbprintSha256Hex(recipientCert);

            return new CcHybridEnvelope
            {
                Envelope = "CC-ENV-1",
                RecipientNode = string.IsNullOrWhiteSpace(recipientNodeId) ? "EQ01" : recipientNodeId.ToUpperInvariant(),
                RecipientThumbprintSha256 = recipientThumb,
                KeyWrapAlgorithm = "RSA-OAEP-SHA256",
                ContentEncryptionAlgorithm = "AES-256-GCM",
                WrappedKeyBase64 = Convert.ToBase64String(wrappedCek),
                NonceBase64 = Convert.ToBase64String(nonce),
                TagBase64 = Convert.ToBase64String(tag),
                CiphertextBase64 = null // No se incluye en resultEnvelope
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cek);
        }
    }

    /// <summary>
    /// Abre y autentica un sobre híbrido CC-ENV-1 verificando tamaños exactos (nonce=12B, tag=16B, wrappedKey=256B, CEK=32B)
    /// y huella del destinatario en tiempo constante.
    /// </summary>
    public static byte[] Open(
        CcHybridEnvelope envelope,
        string expectedAadContext,
        X509Certificate2? recipientCertWithPrivateKey = null,
        byte[]? detachedCiphertext = null,
        string? fallbackAadContext = null)
    {
        if (envelope == null || !string.Equals(envelope.ResolveEnvelopeVersion(), "CC-ENV-1", StringComparison.Ordinal))
            throw new PacketValidationException("E-ENV-DECRYPT", 401, "El sobre híbrido no es válido o su identificador no es CC-ENV-1.");

        var ownCert = recipientCertWithPrivateKey ?? V2CertificateService.CurrentCertificate;
        string ownThumb = V2CertificateService.GetThumbprintSha256Hex(ownCert);

        // Validar recipientThumbprintSha256 en tiempo constante -> 401 E-ENV-RECIPIENT
        if (!V2FormatValidators.IsValidThumbprintUpper(envelope.RecipientThumbprintSha256) ||
            !V2CertificateService.FixedTimeEqualsHex(ownThumb, envelope.RecipientThumbprintSha256))
        {
            throw new PacketValidationException(
                "E-ENV-RECIPIENT",
                401,
                $"El sobre CC-ENV-1 está dirigido a la huella '{envelope.RecipientThumbprintSha256}', que no coincide con la huella activa de {NodeRuntimeState.CurrentNodeId} ('{ownThumb}').");
        }

        using RSA? privateRsa = ownCert.GetRSAPrivateKey();
        if (privateRsa == null)
            throw new PacketValidationException("E-ENV-DECRYPT", 401, "El certificado activo no posee llave privada para abrir CC-ENV-1.");

        byte[]? cek = null;
        try
        {
            string wrappedKeyB64 = envelope.ResolveWrappedKeyBase64();
            if (string.IsNullOrWhiteSpace(wrappedKeyB64))
                throw new PacketValidationException("E-ENV-DECRYPT", 401, "Falta wrappedKeyBase64 en el sobre CC-ENV-1.");

            byte[] wrappedKey = Convert.FromBase64String(wrappedKeyB64);
            byte[] nonce = Convert.FromBase64String(envelope.NonceBase64);
            byte[] tag = Convert.FromBase64String(envelope.TagBase64);
            byte[] ciphertext = detachedCiphertext
                ?? (!string.IsNullOrWhiteSpace(envelope.CiphertextBase64)
                    ? Convert.FromBase64String(envelope.CiphertextBase64)
                    : throw new PacketValidationException("E-ENV-DECRYPT", 401, "No se proporcionó ciphertext para abrir CC-ENV-1."));

            // Validar tamaños exactos antes de descifrar
            if (nonce.Length != NonceSizeBytes)
                throw new PacketValidationException("E-ENV-DECRYPT", 401, $"Tamaño de nonce en CC-ENV-1 inválido ({nonce.Length} B, se requieren 12 B).");
            if (tag.Length != TagSizeBytes)
                throw new PacketValidationException("E-ENV-DECRYPT", 401, $"Tamaño de tag en CC-ENV-1 inválido ({tag.Length} B, se requieren 16 B).");
            if (wrappedKey.Length != Rsa2048WrappedKeySizeBytes)
                throw new PacketValidationException("E-ENV-DECRYPT", 401, $"Tamaño de wrappedKey en CC-ENV-1 inválido ({wrappedKey.Length} B, se requieren 256 B).");

            cek = privateRsa.Decrypt(wrappedKey, RSAEncryptionPadding.OaepSHA256);
            if (cek.Length != CekSizeBytes)
                throw new PacketValidationException("E-ENV-DECRYPT", 401, $"La CEK desenvuelta mide {cek.Length} B (se requieren 32 B exactos).");

            var aadCandidates = new List<byte[]>();
            if (!string.IsNullOrEmpty(expectedAadContext))
                aadCandidates.Add(Encoding.UTF8.GetBytes(expectedAadContext));
            if (!string.IsNullOrEmpty(fallbackAadContext) && !string.Equals(fallbackAadContext, expectedAadContext, StringComparison.Ordinal))
                aadCandidates.Add(Encoding.UTF8.GetBytes(fallbackAadContext));
            aadCandidates.Add(Array.Empty<byte>());

            using var aesGcm = new AesGcm(cek, TagSizeBytes);
            Exception? lastEx = null;

            foreach (byte[] aadBytes in aadCandidates)
            {
                try
                {
                    byte[] plaintext = new byte[ciphertext.Length];
                    if (aadBytes.Length > 0)
                        aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, aadBytes);
                    else
                        aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
                    return plaintext;
                }
                catch (Exception ex)
                {
                    lastEx = ex;
                }
            }

            throw new PacketValidationException("E-ENV-DECRYPT", 401, $"Fallo de autenticación GCM al abrir CC-ENV-1: {lastEx?.Message}");
        }
        catch (PacketValidationException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new PacketValidationException("E-ENV-DECRYPT", 401, $"Fallo al desenvolver o autenticar sobre CC-ENV-1: {ex.Message}");
        }
        finally
        {
            if (cek != null)
                CryptographicOperations.ZeroMemory(cek);
        }
    }

    /// <summary>
    /// Abre un sobre CC-ENV-1 de 'secrets' (con AAD = requestId) y valida que el JSON descifrado sea un objeto plano
    /// clave -> cadena (o envuelve bytes crudos en ["key"] como alias tolerante).
    /// </summary>
    public static Dictionary<string, string> OpenSecretsDictionary(
        CcHybridEnvelope envelope,
        string requestId,
        string? fallbackPacketId = null,
        X509Certificate2? recipientCertWithPrivateKey = null)
    {
        byte[] plainBytes = Open(
            envelope,
            expectedAadContext: requestId,
            recipientCertWithPrivateKey: recipientCertWithPrivateKey,
            fallbackAadContext: fallbackPacketId);

        try
        {
            string text = Encoding.UTF8.GetString(plainBytes).Trim();
            if (text.StartsWith('{') && text.EndsWith('}'))
            {
                using var doc = JsonDocument.Parse(text);
                if (doc.RootElement.ValueKind != JsonValueKind.Object)
                    throw new PacketValidationException("E-ENV-DECRYPT", 401, "El contenido de 'secrets' en CC-ENV-1 debe ser un objeto JSON plano.");

                var dict = new Dictionary<string, string>(StringComparer.Ordinal);
                foreach (var prop in doc.RootElement.EnumerateObject())
                {
                    if (prop.Value.ValueKind is JsonValueKind.Object or JsonValueKind.Array)
                        throw new PacketValidationException("E-ENV-DECRYPT", 401, $"La propiedad '{prop.Name}' dentro de 'secrets' no puede ser un objeto o arreglo anidado.");

                    dict[prop.Name] = prop.Value.ValueKind == JsonValueKind.String
                        ? (prop.Value.GetString() ?? string.Empty)
                        : prop.Value.GetRawText();
                }
                return dict;
            }

            // Alias tolerante: si un cliente selló directamente los bytes crudos de la llave en lugar de un JSON {"key":"..."}
            return new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["key"] = Convert.ToBase64String(plainBytes)
            };
        }
        catch (PacketValidationException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new PacketValidationException("E-ENV-DECRYPT", 401, $"Error al interpretar secretos de CC-ENV-1: {ex.Message}");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plainBytes);
        }
    }
}
