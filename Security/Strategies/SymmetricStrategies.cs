using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ModuloCrypto.Security.Strategies;

internal static class SymmetricKeyHelper
{
    public static readonly string[] NonceAndIvAliases =
    {
        "nonceBase64", "nonce", "ivBase64", "iv", "opt.nonceBase64", "opt.ivBase64"
    };

    public static readonly string[] TagAliases =
    {
        "tagBase64", "tag", "authTagBase64", "authTag", "macBase64"
    };

    public static readonly string[] KeySizeAliases =
    {
        "keySizeBits", "opt.keySizeBits", "keySize"
    };

    public static bool TryDecodeFlexibleBase64(string? input, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(input)) return false;

        string cleaned = input.Trim()
            .Replace("\r", "", StringComparison.Ordinal)
            .Replace("\n", "", StringComparison.Ordinal)
            .Replace(" ", "", StringComparison.Ordinal)
            .Replace('-', '+')
            .Replace('_', '/');

        int mod4 = cleaned.Length % 4;
        if (mod4 == 2) cleaned += "==";
        else if (mod4 == 3) cleaned += "=";
        else if (mod4 == 1) return false;

        try
        {
            bytes = Convert.FromBase64String(cleaned);
            return bytes.Length > 0;
        }
        catch
        {
            return false;
        }
    }

    public static bool TryDecodeHex(string? input, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(input)) return false;

        string cleaned = input.Trim()
            .Replace(" ", "", StringComparison.Ordinal)
            .Replace(":", "", StringComparison.Ordinal)
            .Replace("-", "", StringComparison.Ordinal);

        if (cleaned.Length == 0 || (cleaned.Length % 2) != 0)
            return false;

        for (int i = 0; i < cleaned.Length; i++)
        {
            char c = cleaned[i];
            bool isHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!isHex) return false;
        }

        try
        {
            bytes = Convert.FromHexString(cleaned);
            return bytes.Length > 0;
        }
        catch
        {
            return false;
        }
    }

    public static bool TryGetAnyJsonBase64(string? json, out byte[] bytes, params string[] candidatePropertyNames)
    {
        bytes = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(json) || candidatePropertyNames.Length == 0)
            return false;

        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return false;

            foreach (string candidate in candidatePropertyNames)
            {
                if (TryExtractJsonStringProperty(doc.RootElement, candidate, out string? rawVal) &&
                    !string.IsNullOrWhiteSpace(rawVal) &&
                    TryDecodeFlexibleBase64(rawVal, out bytes))
                {
                    return true;
                }
            }
        }
        catch { }

        return false;
    }

    public static string TryGetAnyJsonString(string? json, params string[] candidatePropertyNames)
    {
        if (string.IsNullOrWhiteSpace(json) || candidatePropertyNames.Length == 0)
            return string.Empty;

        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return string.Empty;

            foreach (string candidate in candidatePropertyNames)
            {
                if (TryExtractJsonStringProperty(doc.RootElement, candidate, out string? rawVal) &&
                    !string.IsNullOrWhiteSpace(rawVal))
                {
                    return rawVal;
                }
            }
        }
        catch { }

        return string.Empty;
    }

    private static bool TryExtractJsonStringProperty(JsonElement root, string candidateName, out string? value)
    {
        value = null;

        // 1. Búsqueda directa en objeto plano (incluyendo llaves con punto como "opt.keySizeBits")
        foreach (var prop in root.EnumerateObject())
        {
            if (prop.Name.Equals(candidateName, StringComparison.OrdinalIgnoreCase))
            {
                value = prop.Value.ValueKind == JsonValueKind.String
                    ? prop.Value.GetString()
                    : prop.Value.GetRawText();
                return !string.IsNullOrWhiteSpace(value);
            }
        }

        // 2. Si tiene prefijo "opt.", buscar también si un tercero serializó un subobjeto "opt": { ... }
        int dotIdx = candidateName.IndexOf('.');
        if (dotIdx > 0 && dotIdx < candidateName.Length - 1)
        {
            string parentName = candidateName[..dotIdx];
            string childName = candidateName[(dotIdx + 1)..];
            foreach (var prop in root.EnumerateObject())
            {
                if (prop.Name.Equals(parentName, StringComparison.OrdinalIgnoreCase) &&
                    prop.Value.ValueKind == JsonValueKind.Object)
                {
                    return TryExtractJsonStringProperty(prop.Value, childName, out value);
                }
            }
        }

        return false;
    }

    /// <summary>
    /// Construye la lista ordenada de candidatos de AAD para descifrado tolerante en AESGCM y CHACHA20:
    /// 1. Encoding.UTF8.GetBytes(packetId) (Estándar v2.0 oficial — prioridad 1)
    /// 2. Array.Empty&lt;byte&gt;() (Paquetes cifrados sin AAD o modo local de terceros)
    /// 3. Encoding.UTF8.GetBytes(requestId) (si existe requestId)
    /// 4. Encoding.UTF8.GetBytes(packetId.ToUpperInvariant()) (si algún equipo serializó el UUID en mayúsculas)
    /// </summary>
    public static List<byte[]> BuildCandidateAads(DecryptionContext? context)
    {
        var list = new List<byte[]>();

        void AddUnique(byte[] candidate)
        {
            if (!list.Any(existing => existing.AsSpan().SequenceEqual(candidate)))
                list.Add(candidate);
        }

        string? packetId = context?.PacketId?.Trim();
        string? requestId = context?.RequestId?.Trim();

        if (!string.IsNullOrEmpty(packetId))
            AddUnique(Encoding.UTF8.GetBytes(packetId));

        AddUnique(Array.Empty<byte>());

        if (!string.IsNullOrEmpty(requestId))
            AddUnique(Encoding.UTF8.GetBytes(requestId));

        if (!string.IsNullOrEmpty(packetId))
        {
            AddUnique(Encoding.UTF8.GetBytes(packetId.ToUpperInvariant()));
            AddUnique(Encoding.UTF8.GetBytes(packetId.ToLowerInvariant()));
        }

        return list;
    }

    /// <summary>
    /// Construye la lista deduplicada de llaves candidatas del tamaño requerido en orden de prioridad:
    /// 1. Base64 estándar o URL-safe (si decodifica exactamente a requiredBytes, o 16/32 B en AESGCM)
    /// 2. Hexadecimal (si trimmed.Length == requiredBytes * 2 y decodifica a requiredBytes)
    /// 3. Bytes UTF-8 directos (si Encoding.UTF8.GetBytes(trimmed).Length == requiredBytes)
    /// 4. SHA-256 de la cadena UTF-8 (recortado a requiredBytes)
    /// 5. HKDF-SHA256 (sin salt, info = etiqueta del algoritmo, tanto sobre UTF-8 como sobre bytes Base64 decodificados).
    /// </summary>
    public static List<byte[]> BuildCandidateKeys(string? input, int requiredBytes, string algorithmCode)
    {
        var candidates = new List<byte[]>();
        bool isAesGcm = string.Equals(algorithmCode, "AESGCM", StringComparison.OrdinalIgnoreCase);
        bool isTripleDes = string.Equals(algorithmCode, "TRIPLEDES", StringComparison.OrdinalIgnoreCase);

        bool IsAcceptedLen(int len) =>
            len == requiredBytes ||
            (isAesGcm && len is 16 or 32) ||
            (isTripleDes && len == 16);

        void AddCandidate(byte[]? keyBytes)
        {
            if (keyBytes == null) return;

            if (isTripleDes && keyBytes.Length == 16)
            {
                // Expansión estándar 2-key 3DES (16 B -> 24 B = K1||K2||K1)
                byte[] expanded24 = new byte[24];
                Buffer.BlockCopy(keyBytes, 0, expanded24, 0, 16);
                Buffer.BlockCopy(keyBytes, 0, expanded24, 16, 8);
                AddCandidate(expanded24);
                CryptographicOperations.ZeroMemory(expanded24);
                return;
            }

            bool validLen = keyBytes.Length == requiredBytes || (isAesGcm && keyBytes.Length is 16 or 32);
            if (!validLen) return;

            if (!candidates.Any(existing => existing.AsSpan().SequenceEqual(keyBytes)))
            {
                candidates.Add(keyBytes.ToArray());
            }
        }

        if (string.IsNullOrWhiteSpace(input))
        {
            candidates.Add(new byte[requiredBytes]);
            return candidates;
        }

        string trimmed = input.Trim();
        byte[] utf8Bytes = Encoding.UTF8.GetBytes(trimmed);
        byte[]? decodedB64 = null;

        try
        {
            // Prioridad 1: Base64 estándar o URL-safe del tamaño exacto
            if (TryDecodeFlexibleBase64(trimmed, out byte[] b64))
            {
                decodedB64 = b64;
                if (IsAcceptedLen(b64.Length))
                {
                    AddCandidate(b64);
                }
            }

            // Prioridad 2: Hexadecimal del tamaño exacto
            if (TryDecodeHex(trimmed, out byte[] hexBytes))
            {
                if (IsAcceptedLen(hexBytes.Length))
                {
                    AddCandidate(hexBytes);
                }
                CryptographicOperations.ZeroMemory(hexBytes);
            }

            // Prioridad 3: Bytes UTF-8 directos si miden exactamente requiredBytes (o 16 B en 3DES)
            if (IsAcceptedLen(utf8Bytes.Length))
            {
                AddCandidate(utf8Bytes);
            }

            // Prioridad 4: SHA-256 de la cadena UTF-8 recortado a requiredBytes
            byte[] sha256Full = SHA256.HashData(utf8Bytes);
            AddCandidate(sha256Full[..requiredBytes]);
            if (isAesGcm && requiredBytes == 32)
            {
                AddCandidate(sha256Full[..16]);
            }
            CryptographicOperations.ZeroMemory(sha256Full);

            // Si Base64 decodificó a otra longitud distinta, probar también SHA-256 sobre esos bytes crudos
            if (decodedB64 is { Length: > 0 } && decodedB64.Length != requiredBytes)
            {
                byte[] shaFromB64 = SHA256.HashData(decodedB64);
                AddCandidate(shaFromB64[..requiredBytes]);
                CryptographicOperations.ZeroMemory(shaFromB64);
            }

            // Prioridad 5: HKDF-SHA256 (sin salt, info = etiqueta del algoritmo) sobre UTF-8 y sobre Base64 decodificado
            string[] hkdfLabels = GetHkdfLabelsForAlgorithm(algorithmCode);
            foreach (string label in hkdfLabels)
            {
                byte[] infoBytes = Encoding.UTF8.GetBytes(label);
                byte[] hkdfUtf8 = HKDF.DeriveKey(HashAlgorithmName.SHA256, utf8Bytes, requiredBytes, salt: null, info: infoBytes);
                AddCandidate(hkdfUtf8);
                CryptographicOperations.ZeroMemory(hkdfUtf8);

                if (decodedB64 is { Length: > 0 })
                {
                    byte[] hkdfB64 = HKDF.DeriveKey(HashAlgorithmName.SHA256, decodedB64, requiredBytes, salt: null, info: infoBytes);
                    AddCandidate(hkdfB64);
                    CryptographicOperations.ZeroMemory(hkdfB64);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(utf8Bytes);
            if (decodedB64 != null)
                CryptographicOperations.ZeroMemory(decodedB64);
        }

        if (candidates.Count == 0)
            candidates.Add(new byte[requiredBytes]);

        return candidates;
    }

    public static byte[] ResolveStrictEmissionKey(string? optionalPassphrase, int defaultRequiredBytes, bool allowAes128 = false)
    {
        if (string.IsNullOrWhiteSpace(optionalPassphrase))
            return RandomNumberGenerator.GetBytes(defaultRequiredBytes);

        string trimmed = optionalPassphrase.Trim();
        if (TryDecodeFlexibleBase64(trimmed, out byte[] b64))
        {
            if (b64.Length == defaultRequiredBytes || (allowAes128 && b64.Length == 16))
                return b64;
            CryptographicOperations.ZeroMemory(b64);
        }

        if (TryDecodeHex(trimmed, out byte[] hex))
        {
            if (hex.Length == defaultRequiredBytes || (allowAes128 && hex.Length == 16))
                return hex;
            CryptographicOperations.ZeroMemory(hex);
        }

        byte[] utf8 = Encoding.UTF8.GetBytes(trimmed);
        try
        {
            if (utf8.Length == defaultRequiredBytes || (allowAes128 && utf8.Length == 16))
                return utf8.ToArray();

            byte[] sha = SHA256.HashData(utf8);
            try
            {
                return sha[..defaultRequiredBytes];
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sha);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(utf8);
        }
    }

    public static void ZeroCandidateKeys(List<byte[]>? candidates)
    {
        if (candidates == null) return;
        foreach (var k in candidates)
        {
            if (k != null)
                CryptographicOperations.ZeroMemory(k);
        }
    }

    private static string[] GetHkdfLabelsForAlgorithm(string algorithmCode) =>
        algorithmCode.ToUpperInvariant() switch
        {
            "AESGCM" => new[] { "AESGCM-KEY", "AES-GCM", "AES256-GCM" },
            "CHACHA20" => new[] { "CHACHA20-KEY", "CHACHA20-POLY1305" },
            "DES" => new[] { "DES56:KEY", "DES-KEY" },
            "TRIPLEDES" => new[] { "TRIPLEDES:KEY", "3DES-KEY" },
            _ => new[] { $"{algorithmCode.ToUpperInvariant()}-KEY" }
        };
}

/// <summary>1. AESGCM — AES-256-GCM (Equipo Dueño Oficial: EQ01)</summary>
public sealed class AesGcmStrategy : ICryptoStrategy
{
    public CryptoAlgorithmInfo Info { get; } = new()
    {
        Code = "AESGCM",
        DisplayName = "AES-256-GCM",
        Category = "Simétrico AEAD",
        Description = "Cifrado autenticado AES de 128/256 bits en modo Galois/Counter (Nonce 96-bit, Tag 128-bit)."
    };

    public CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase = null)
        => Encrypt(plainBytes, optionalPassphrase, packetId: null);

    public CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase, string? packetId)
    {
        byte[] key = SymmetricKeyHelper.ResolveStrictEmissionKey(optionalPassphrase, defaultRequiredBytes: 32, allowAes128: true);
        try
        {
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] cipher = new byte[plainBytes.Length];
            byte[] tag = new byte[16];
            byte[] aad = !string.IsNullOrWhiteSpace(packetId)
                ? Encoding.UTF8.GetBytes(packetId.Trim())
                : Array.Empty<byte>();

            using (var aes = new AesGcm(key, 16))
            {
                if (aad.Length > 0)
                    aes.Encrypt(nonce, plainBytes, cipher, tag, aad);
                else
                    aes.Encrypt(nonce, plainBytes, cipher, tag);
            }

            // Emisión estricta Tabla 4.2 del Estándar v2.0: exclusivamente keySizeBits, nonceBase64 y tagBase64
            var pubDict = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["keySizeBits"] = (key.Length * 8).ToString(),
                ["nonceBase64"] = Convert.ToBase64String(nonce),
                ["tagBase64"] = Convert.ToBase64String(tag)
            };

            return new CryptoOperationResult
            {
                AlgorithmCode = Info.Code,
                OutputBytes = cipher,
                SecretKeyBase64 = Convert.ToBase64String(key),
                PublicParametersJson = JsonSerializer.Serialize(pubDict),
                Summary = $"AES-{key.Length * 8}-GCM cifrado ({cipher.Length} bytes, Tag AEAD 128-bit)."
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public CryptoOperationResult Decrypt(byte[] cipherBytes, string secretKeyBase64, string publicParametersJson)
        => Decrypt(cipherBytes, secretKeyBase64, publicParametersJson, context: null);

    public CryptoOperationResult Decrypt(
        byte[] cipherBytes,
        string secretKeyBase64,
        string publicParametersJson,
        DecryptionContext? context)
    {
        string keySizeStr = SymmetricKeyHelper.TryGetAnyJsonString(publicParametersJson, SymmetricKeyHelper.KeySizeAliases);
        int requiredKeyBytes = string.Equals(keySizeStr, "128", StringComparison.OrdinalIgnoreCase) ? 16 : 32;

        var candidateKeys = SymmetricKeyHelper.BuildCandidateKeys(secretKeyBase64, requiredKeyBytes, Info.Code);
        var candidateAads = SymmetricKeyHelper.BuildCandidateAads(context);

        try
        {
            bool hasNonce = SymmetricKeyHelper.TryGetAnyJsonBase64(publicParametersJson, out byte[] nonce, SymmetricKeyHelper.NonceAndIvAliases);
            bool hasTag = SymmetricKeyHelper.TryGetAnyJsonBase64(publicParametersJson, out byte[] tag, SymmetricKeyHelper.TagAliases);

            if (hasNonce && hasTag)
            {
                if (nonce.Length != 12)
                    throw new CryptographicException($"El nonce/IV de AES-GCM debe medir 12 bytes (recibido: {nonce.Length} bytes).");
                if (tag.Length != 16)
                    throw new CryptographicException($"El tag AEAD de AES-GCM debe medir 16 bytes (recibido: {tag.Length} bytes).");

                Exception? lastAuthEx = null;
                foreach (byte[] keyCandidate in candidateKeys)
                {
                    using var aes = new AesGcm(keyCandidate, 16);
                    foreach (byte[] aadCandidate in candidateAads)
                    {
                        try
                        {
                            byte[] plain = new byte[cipherBytes.Length];
                            if (aadCandidate.Length > 0)
                                aes.Decrypt(nonce, cipherBytes, tag, plain, aadCandidate);
                            else
                                aes.Decrypt(nonce, cipherBytes, tag, plain);

                            return new CryptoOperationResult
                            {
                                AlgorithmCode = Info.Code,
                                OutputBytes = plain,
                                SecretKeyBase64 = secretKeyBase64,
                                PublicParametersJson = publicParametersJson,
                                Summary = $"AES-GCM autenticado y descifrado ({plain.Length} bytes)."
                            };
                        }
                        catch (Exception ex)
                        {
                            lastAuthEx = ex;
                        }
                    }
                }

                throw new CryptographicException(
                    "Falló la autenticación del tag AES-GCM con todas las variantes de llave y candidatos de AAD.",
                    lastAuthEx);
            }

            // Solo si NO vinieron nonce y tag en el JSON, probar layouts empaquetados ([12B nonce][16B tag][cipher] y [12B nonce][cipher][16B tag])
            if (cipherBytes.Length < 28)
                throw new CryptographicException("No se encontraron nonce/tag en publicParameters y los datos cifrados miden menos de 28 bytes.");

            foreach (byte[] keyCandidate in candidateKeys)
            {
                using var aesFallback = new AesGcm(keyCandidate, 16);
                foreach (byte[] aadCandidate in candidateAads)
                {
                    try
                    {
                        byte[] nA = cipherBytes[..12];
                        byte[] tA = cipherBytes[12..28];
                        byte[] cA = cipherBytes[28..];
                        byte[] plainA = new byte[cA.Length];
                        if (aadCandidate.Length > 0)
                            aesFallback.Decrypt(nA, cA, tA, plainA, aadCandidate);
                        else
                            aesFallback.Decrypt(nA, cA, tA, plainA);

                        return new CryptoOperationResult
                        {
                            AlgorithmCode = Info.Code,
                            OutputBytes = plainA,
                            SecretKeyBase64 = secretKeyBase64,
                            PublicParametersJson = publicParametersJson,
                            Summary = $"AES-GCM (formato empaquetado nonce+tag+cipher) descifrado ({plainA.Length} bytes)."
                        };
                    }
                    catch { }

                    try
                    {
                        byte[] nB = cipherBytes[..12];
                        byte[] cB = cipherBytes[12..^16];
                        byte[] tB = cipherBytes[^16..];
                        byte[] plainB = new byte[cB.Length];
                        if (aadCandidate.Length > 0)
                            aesFallback.Decrypt(nB, cB, tB, plainB, aadCandidate);
                        else
                            aesFallback.Decrypt(nB, cB, tB, plainB);

                        return new CryptoOperationResult
                        {
                            AlgorithmCode = Info.Code,
                            OutputBytes = plainB,
                            SecretKeyBase64 = secretKeyBase64,
                            PublicParametersJson = publicParametersJson,
                            Summary = $"AES-GCM (formato empaquetado nonce+cipher+tag) descifrado ({plainB.Length} bytes)."
                        };
                    }
                    catch { }
                }
            }

            throw new CryptographicException("No fue posible autenticar ni descifrar el payload AES-GCM empaquetado.");
        }
        finally
        {
            SymmetricKeyHelper.ZeroCandidateKeys(candidateKeys);
        }
    }
}

/// <summary>2. DES — DES 56-bit (Equipo Dueño Oficial: EQ01)</summary>
public sealed class DesStrategy : ICryptoStrategy
{
    public CryptoAlgorithmInfo Info { get; } = new()
    {
        Code = "DES",
        DisplayName = "DES 56-bit",
        Category = "Simétrico Clásico",
        Description = "Data Encryption Standard con llave efectiva de 56 bits (8 bytes con paridad, bloque 64-bit, CBC/PKCS7)."
    };

    public CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase = null)
    {
        using var des = DES.Create();
        des.Mode = CipherMode.CBC;
        des.Padding = PaddingMode.PKCS7;
        byte[]? rawKey = null;
        try
        {
            if (!string.IsNullOrWhiteSpace(optionalPassphrase))
            {
                rawKey = SymmetricKeyHelper.ResolveStrictEmissionKey(optionalPassphrase, defaultRequiredBytes: 8);
                des.Key = rawKey;
            }
            else
            {
                des.GenerateKey();
                rawKey = des.Key;
            }
            des.GenerateIV();

            byte[] cipher = des.EncryptCbc(plainBytes, des.IV, PaddingMode.PKCS7);

            // Emisión estricta Tabla 4.2 del Estándar v2.0: exclusivamente mode="CBC", padding="PKCS7", ivBase64
            var pubDict = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["mode"] = "CBC",
                ["padding"] = "PKCS7",
                ["ivBase64"] = Convert.ToBase64String(des.IV)
            };

            return new CryptoOperationResult
            {
                AlgorithmCode = Info.Code,
                OutputBytes = cipher,
                SecretKeyBase64 = Convert.ToBase64String(rawKey),
                PublicParametersJson = JsonSerializer.Serialize(pubDict),
                Summary = $"DES 56-bit cifrado ({cipher.Length} bytes, CBC/PKCS7)."
            };
        }
        finally
        {
            if (rawKey != null) CryptographicOperations.ZeroMemory(rawKey);
        }
    }

    public CryptoOperationResult Decrypt(byte[] cipherBytes, string secretKeyBase64, string publicParametersJson)
        => Decrypt(cipherBytes, secretKeyBase64, publicParametersJson, context: null);

    public CryptoOperationResult Decrypt(
        byte[] cipherBytes,
        string secretKeyBase64,
        string publicParametersJson,
        DecryptionContext? context)
    {
        var candidateKeys = SymmetricKeyHelper.BuildCandidateKeys(secretKeyBase64, 8, Info.Code);
        try
        {
            byte[] iv;
            byte[] actualCipher;

            if (SymmetricKeyHelper.TryGetAnyJsonBase64(publicParametersJson, out byte[] jsonIv, SymmetricKeyHelper.NonceAndIvAliases))
            {
                if (jsonIv.Length != 8)
                    throw new CryptographicException($"El IV de DES debe medir 8 bytes (recibido: {jsonIv.Length} bytes).");
                iv = jsonIv;
                actualCipher = cipherBytes;
            }
            else
            {
                if (cipherBytes.Length <= 8)
                    throw new CryptographicException("Payload DES empaquetado demasiado corto para extraer IV de 8 bytes.");
                iv = cipherBytes[..8];
                actualCipher = cipherBytes[8..];
            }

            Exception? lastEx = null;
            foreach (byte[] keyCandidate in candidateKeys)
            {
                if (keyCandidate.Length != 8) continue;
                try
                {
                    using var des = DES.Create();
                    des.Key = keyCandidate;
                    byte[] plain = des.DecryptCbc(actualCipher, iv, PaddingMode.PKCS7);

                    return new CryptoOperationResult
                    {
                        AlgorithmCode = Info.Code,
                        OutputBytes = plain,
                        SecretKeyBase64 = secretKeyBase64,
                        PublicParametersJson = publicParametersJson,
                        Summary = $"DES 56-bit descifrado ({plain.Length} bytes)."
                    };
                }
                catch (Exception ex)
                {
                    lastEx = ex;
                }
            }

            throw new CryptographicException("No fue posible descifrar el payload DES con las llaves candidatas.", lastEx);
        }
        finally
        {
            SymmetricKeyHelper.ZeroCandidateKeys(candidateKeys);
        }
    }
}

/// <summary>3. TRIPLEDES — Triple DES / 3DES (Equipo Dueño Oficial: EQ02)</summary>
public sealed class TripleDesStrategy : ICryptoStrategy
{
    public CryptoAlgorithmInfo Info { get; } = new()
    {
        Code = "TRIPLEDES",
        DisplayName = "Triple DES / 3DES",
        Category = "Simétrico Bloque",
        Description = "Triple Data Encryption Algorithm (EDE 192-bit, CBC/PKCS7)."
    };

    public CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase = null)
    {
        using var tdes = TripleDES.Create();
        tdes.Mode = CipherMode.CBC;
        tdes.Padding = PaddingMode.PKCS7;
        byte[]? rawKey = null;
        try
        {
            if (!string.IsNullOrWhiteSpace(optionalPassphrase))
            {
                rawKey = SymmetricKeyHelper.ResolveStrictEmissionKey(optionalPassphrase, defaultRequiredBytes: 24);
                tdes.Key = rawKey;
            }
            else
            {
                tdes.GenerateKey();
                rawKey = tdes.Key;
            }
            tdes.GenerateIV();

            byte[] cipher = tdes.EncryptCbc(plainBytes, tdes.IV, PaddingMode.PKCS7);
            var pubDict = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["mode"] = "CBC",
                ["padding"] = "PKCS7",
                ["ivBase64"] = Convert.ToBase64String(tdes.IV)
            };

            return new CryptoOperationResult
            {
                AlgorithmCode = Info.Code,
                OutputBytes = cipher,
                SecretKeyBase64 = Convert.ToBase64String(rawKey),
                PublicParametersJson = JsonSerializer.Serialize(pubDict),
                Summary = $"Triple DES cifrado ({cipher.Length} bytes)."
            };
        }
        finally
        {
            if (rawKey != null) CryptographicOperations.ZeroMemory(rawKey);
        }
    }

    public CryptoOperationResult Decrypt(byte[] cipherBytes, string secretKeyBase64, string publicParametersJson)
        => Decrypt(cipherBytes, secretKeyBase64, publicParametersJson, context: null);

    public CryptoOperationResult Decrypt(
        byte[] cipherBytes,
        string secretKeyBase64,
        string publicParametersJson,
        DecryptionContext? context)
    {
        var candidateKeys = SymmetricKeyHelper.BuildCandidateKeys(secretKeyBase64, 24, Info.Code);
        try
        {
            byte[] iv;
            byte[] actualCipher;

            if (SymmetricKeyHelper.TryGetAnyJsonBase64(publicParametersJson, out byte[] jsonIv, SymmetricKeyHelper.NonceAndIvAliases))
            {
                if (jsonIv.Length != 8)
                    throw new CryptographicException($"El IV de TripleDES debe medir 8 bytes (recibido: {jsonIv.Length} bytes).");
                iv = jsonIv;
                actualCipher = cipherBytes;
            }
            else
            {
                if (cipherBytes.Length <= 8)
                    throw new CryptographicException("Payload 3DES empaquetado demasiado corto para extraer IV.");
                iv = cipherBytes[..8];
                actualCipher = cipherBytes[8..];
            }

            Exception? lastEx = null;
            foreach (byte[] keyCandidate in candidateKeys)
            {
                if (keyCandidate.Length != 24) continue;
                try
                {
                    using var tdes = TripleDES.Create();
                    tdes.Key = keyCandidate;
                    byte[] plain = tdes.DecryptCbc(actualCipher, iv, PaddingMode.PKCS7);

                    return new CryptoOperationResult
                    {
                        AlgorithmCode = Info.Code,
                        OutputBytes = plain,
                        SecretKeyBase64 = secretKeyBase64,
                        PublicParametersJson = publicParametersJson,
                        Summary = $"Triple DES descifrado ({plain.Length} bytes)."
                    };
                }
                catch (Exception ex)
                {
                    lastEx = ex;
                }
            }

            throw new CryptographicException("No fue posible descifrar el payload TripleDES con las llaves candidatas.", lastEx);
        }
        finally
        {
            SymmetricKeyHelper.ZeroCandidateKeys(candidateKeys);
        }
    }
}

/// <summary>4. CHACHA20 — ChaCha20-Poly1305 (Equipo Dueño Oficial: EQ02)</summary>
public sealed class ChaCha20Strategy : ICryptoStrategy
{
    public CryptoAlgorithmInfo Info { get; } = new()
    {
        Code = "CHACHA20",
        DisplayName = "ChaCha20-Poly1305",
        Category = "Simétrico Stream AEAD",
        Description = "Cifrado de flujo ChaCha20 (256-bit) con autenticación MAC Poly1305 (RFC 8439)."
    };

    public CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase = null)
        => Encrypt(plainBytes, optionalPassphrase, packetId: null);

    public CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase, string? packetId)
    {
        byte[] key = SymmetricKeyHelper.ResolveStrictEmissionKey(optionalPassphrase, defaultRequiredBytes: 32);
        try
        {
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] cipher = new byte[plainBytes.Length];
            byte[] tag = new byte[16];
            byte[] aad = !string.IsNullOrWhiteSpace(packetId)
                ? Encoding.UTF8.GetBytes(packetId.Trim())
                : Array.Empty<byte>();

            if (ChaCha20Poly1305.IsSupported)
            {
                using var cc = new ChaCha20Poly1305(key);
                if (aad.Length > 0)
                    cc.Encrypt(nonce, plainBytes, cipher, tag, aad);
                else
                    cc.Encrypt(nonce, plainBytes, cipher, tag);
            }
            else
            {
                cipher = ChaCha20Transform(key, nonce, 1, plainBytes);
                tag = ComputeAuthTag(key, nonce, cipher, aad);
            }

            var pubDict = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["nonceBase64"] = Convert.ToBase64String(nonce),
                ["tagBase64"] = Convert.ToBase64String(tag)
            };

            return new CryptoOperationResult
            {
                AlgorithmCode = Info.Code,
                OutputBytes = cipher,
                SecretKeyBase64 = Convert.ToBase64String(key),
                PublicParametersJson = JsonSerializer.Serialize(pubDict),
                Summary = $"ChaCha20-Poly1305 cifrado ({cipher.Length} bytes)."
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public CryptoOperationResult Decrypt(byte[] cipherBytes, string secretKeyBase64, string publicParametersJson)
        => Decrypt(cipherBytes, secretKeyBase64, publicParametersJson, context: null);

    public CryptoOperationResult Decrypt(
        byte[] cipherBytes,
        string secretKeyBase64,
        string publicParametersJson,
        DecryptionContext? context)
    {
        var candidateKeys = SymmetricKeyHelper.BuildCandidateKeys(secretKeyBase64, 32, Info.Code);
        var candidateAads = SymmetricKeyHelper.BuildCandidateAads(context);

        try
        {
            bool hasNonce = SymmetricKeyHelper.TryGetAnyJsonBase64(publicParametersJson, out byte[] nonce, SymmetricKeyHelper.NonceAndIvAliases);
            bool hasTag = SymmetricKeyHelper.TryGetAnyJsonBase64(publicParametersJson, out byte[] tag, SymmetricKeyHelper.TagAliases);

            if (hasNonce && hasTag)
            {
                if (nonce.Length != 12)
                    throw new CryptographicException($"El nonce de ChaCha20-Poly1305 debe medir 12 bytes (recibido: {nonce.Length} bytes).");
                if (tag.Length != 16)
                    throw new CryptographicException($"El tag de ChaCha20-Poly1305 debe medir 16 bytes (recibido: {tag.Length} bytes).");

                string mode = SymmetricKeyHelper.TryGetAnyJsonString(publicParametersJson, "mode", "opt.mode");
                Exception? lastEx = null;

                foreach (byte[] keyCandidate in candidateKeys)
                {
                    foreach (byte[] aadCandidate in candidateAads)
                    {
                        try
                        {
                            byte[] plain = DecryptWithNonceAndTag(keyCandidate, nonce, tag, cipherBytes, aadCandidate, mode);
                            return new CryptoOperationResult
                            {
                                AlgorithmCode = Info.Code,
                                OutputBytes = plain,
                                SecretKeyBase64 = secretKeyBase64,
                                PublicParametersJson = publicParametersJson,
                                Summary = $"ChaCha20-Poly1305 autenticado y descifrado ({plain.Length} bytes)."
                            };
                        }
                        catch (Exception ex)
                        {
                            lastEx = ex;
                        }
                    }
                }

                throw new CryptographicException("Falló la autenticación del tag ChaCha20-Poly1305 con todas las llaves y candidatos de AAD.", lastEx);
            }

            if (cipherBytes.Length < 28)
                throw new CryptographicException("No se encontraron nonce/tag en publicParameters y los datos cifrados miden menos de 28 bytes.");

            foreach (byte[] keyCandidate in candidateKeys)
            {
                foreach (byte[] aadCandidate in candidateAads)
                {
                    try
                    {
                        byte[] nA = cipherBytes[..12];
                        byte[] tA = cipherBytes[12..28];
                        byte[] cA = cipherBytes[28..];
                        byte[] plainA = DecryptWithNonceAndTag(keyCandidate, nA, tA, cA, aadCandidate, string.Empty);
                        return new CryptoOperationResult
                        {
                            AlgorithmCode = Info.Code,
                            OutputBytes = plainA,
                            SecretKeyBase64 = secretKeyBase64,
                            PublicParametersJson = publicParametersJson,
                            Summary = $"ChaCha20-Poly1305 (formato empaquetado nonce+tag+cipher) descifrado ({plainA.Length} bytes)."
                        };
                    }
                    catch { }

                    try
                    {
                        byte[] nB = cipherBytes[..12];
                        byte[] cB = cipherBytes[12..^16];
                        byte[] tB = cipherBytes[^16..];
                        byte[] plainB = DecryptWithNonceAndTag(keyCandidate, nB, tB, cB, aadCandidate, string.Empty);
                        return new CryptoOperationResult
                        {
                            AlgorithmCode = Info.Code,
                            OutputBytes = plainB,
                            SecretKeyBase64 = secretKeyBase64,
                            PublicParametersJson = publicParametersJson,
                            Summary = $"ChaCha20-Poly1305 (formato empaquetado nonce+cipher+tag) descifrado ({plainB.Length} bytes)."
                        };
                    }
                    catch { }
                }
            }

            throw new CryptographicException("No fue posible autenticar ni descifrar el payload ChaCha20-Poly1305 empaquetado.");
        }
        finally
        {
            SymmetricKeyHelper.ZeroCandidateKeys(candidateKeys);
        }
    }

    private static byte[] DecryptWithNonceAndTag(byte[] key, byte[] nonce, byte[] tag, byte[] cipherBytes, byte[] aad, string mode)
    {
        if (ChaCha20Poly1305.IsSupported && mode != "RFC8439-ChaCha20-Managed")
        {
            try
            {
                byte[] plain = new byte[cipherBytes.Length];
                using var cc = new ChaCha20Poly1305(key);
                if (aad.Length > 0)
                    cc.Decrypt(nonce, cipherBytes, tag, plain, aad);
                else
                    cc.Decrypt(nonce, cipherBytes, tag, plain);
                return plain;
            }
            catch (CryptographicException) when (string.IsNullOrEmpty(mode) || !string.Equals(mode, "RFC8439-ChaCha20", StringComparison.OrdinalIgnoreCase))
            {
                // Si el nodo emisor etiquetó un modo gestionado/externo distinto, probar ComputeAuthTag antes de descartar la llave
            }
        }

        byte[] expected = ComputeAuthTag(key, nonce, cipherBytes, aad);
        if (!CryptographicOperations.FixedTimeEquals(expected, tag))
            throw new CryptographicException("Tag de autenticación ChaCha20 inválido.");
        return ChaCha20Transform(key, nonce, 1, cipherBytes);
    }

    private static byte[] ComputeAuthTag(byte[] key, byte[] nonce, byte[] cipher, byte[] aad)
    {
        byte[] polyKey = ChaCha20Block(key, 0, nonce)[..32];
        try
        {
            using var hmac = new HMACSHA256(polyKey);
            byte[] input = new byte[nonce.Length + aad.Length + cipher.Length];
            Buffer.BlockCopy(nonce, 0, input, 0, nonce.Length);
            if (aad.Length > 0)
                Buffer.BlockCopy(aad, 0, input, nonce.Length, aad.Length);
            Buffer.BlockCopy(cipher, 0, input, nonce.Length + aad.Length, cipher.Length);
            return hmac.ComputeHash(input)[..16];
        }
        finally
        {
            CryptographicOperations.ZeroMemory(polyKey);
        }
    }

    private static byte[] ChaCha20Transform(byte[] key, byte[] nonce, uint counter, byte[] data)
    {
        byte[] output = new byte[data.Length];
        int offset = 0;
        while (offset < data.Length)
        {
            byte[] block = ChaCha20Block(key, counter++, nonce);
            int take = Math.Min(64, data.Length - offset);
            for (int i = 0; i < take; i++)
                output[offset + i] = (byte)(data[offset + i] ^ block[i]);
            CryptographicOperations.ZeroMemory(block);
            offset += take;
        }
        return output;
    }

    private static byte[] ChaCha20Block(byte[] key, uint counter, byte[] nonce)
    {
        uint[] state = new uint[16];
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        for (int i = 0; i < 8; i++)
            state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key.AsSpan(i * 4, 4));
        state[12] = counter;
        for (int i = 0; i < 3; i++)
            state[13 + i] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.AsSpan(i * 4, 4));

        uint[] working = (uint[])state.Clone();
        for (int r = 0; r < 10; r++)
        {
            QuarterRound(working, 0, 4, 8, 12);
            QuarterRound(working, 1, 5, 9, 13);
            QuarterRound(working, 2, 6, 10, 14);
            QuarterRound(working, 3, 7, 11, 15);
            QuarterRound(working, 0, 5, 10, 15);
            QuarterRound(working, 1, 6, 11, 12);
            QuarterRound(working, 2, 7, 8, 13);
            QuarterRound(working, 3, 4, 9, 14);
        }

        byte[] output = new byte[64];
        for (int i = 0; i < 16; i++)
            BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(i * 4, 4), working[i] + state[i]);
        return output;
    }

    private static void QuarterRound(uint[] x, int a, int b, int c, int d)
    {
        x[a] += x[b]; x[d] = BitOperationsRotateLeft(x[d] ^ x[a], 16);
        x[c] += x[d]; x[b] = BitOperationsRotateLeft(x[b] ^ x[c], 12);
        x[a] += x[b]; x[d] = BitOperationsRotateLeft(x[d] ^ x[a], 8);
        x[c] += x[d]; x[b] = BitOperationsRotateLeft(x[b] ^ x[c], 7);
    }

    private static uint BitOperationsRotateLeft(uint value, int shift) => (value << shift) | (value >> (32 - shift));
}
