using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ModuloCrypto.Security.Strategies;

internal static class SymmetricKeyHelper
{
    public static byte[] ResolveKey(string secretKeyBase64OrPassphrase, int requiredBytes)
    {
        if (!string.IsNullOrWhiteSpace(secretKeyBase64OrPassphrase))
        {
            try
            {
                byte[] decoded = Convert.FromBase64String(secretKeyBase64OrPassphrase.Trim());
                if (decoded.Length == requiredBytes)
                    return decoded;
            }
            catch
            {
                // No es Base64 exacto: derivar mediante SHA-256 desde passphrase
            }
            return SHA256.HashData(Encoding.UTF8.GetBytes(secretKeyBase64OrPassphrase))[..requiredBytes];
        }

        return new byte[requiredBytes];
    }

    public static bool TryGetJsonBase64(string? json, string propertyName, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(json)) return false;

        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return false;
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                if (prop.Name.Equals(propertyName, StringComparison.OrdinalIgnoreCase) &&
                    prop.Value.ValueKind == JsonValueKind.String)
                {
                    string? val = prop.Value.GetString();
                    if (!string.IsNullOrWhiteSpace(val))
                    {
                        bytes = Convert.FromBase64String(val);
                        return true;
                    }
                }
            }
        }
        catch { }

        return false;
    }

    public static string TryGetJsonString(string? json, string propertyName)
    {
        if (string.IsNullOrWhiteSpace(json)) return string.Empty;
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return string.Empty;
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                if (prop.Name.Equals(propertyName, StringComparison.OrdinalIgnoreCase) &&
                    prop.Value.ValueKind == JsonValueKind.String)
                {
                    return prop.Value.GetString() ?? string.Empty;
                }
            }
        }
        catch { }
        return string.Empty;
    }
}

/// <summary>1. AESGCM — AES-256-GCM</summary>
public sealed class AesGcmStrategy : ICryptoStrategy
{
    public CryptoAlgorithmInfo Info { get; } = new()
    {
        Code = "AESGCM",
        DisplayName = "AES-256-GCM",
        Category = "Simétrico AEAD",
        Description = "Cifrado autenticado AES de 256 bits en modo Galois/Counter (Nonce 96-bit, Tag 128-bit)."
    };

    public CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase = null)
    {
        byte[] key = string.IsNullOrWhiteSpace(optionalPassphrase)
            ? RandomNumberGenerator.GetBytes(32)
            : SHA256.HashData(Encoding.UTF8.GetBytes(optionalPassphrase));
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] cipher = new byte[plainBytes.Length];
        byte[] tag = new byte[16];

        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, plainBytes, cipher, tag);

        string pubJson = JsonSerializer.Serialize(new
        {
            mode = "AES-256-GCM",
            nonce = Convert.ToBase64String(nonce),
            tag = Convert.ToBase64String(tag)
        });

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = cipher,
            SecretKeyBase64 = Convert.ToBase64String(key),
            PublicParametersJson = pubJson,
            Summary = $"AES-256-GCM cifrado ({cipher.Length} bytes, Tag AEAD 128-bit)."
        };
    }

    public CryptoOperationResult Decrypt(byte[] cipherBytes, string secretKeyBase64, string publicParametersJson)
    {
        byte[] key = SymmetricKeyHelper.ResolveKey(secretKeyBase64, 32);

        // Prioridad 1: Formato nativo ModuloCrypto (nonce y tag en JSON)
        if (SymmetricKeyHelper.TryGetJsonBase64(publicParametersJson, "nonce", out byte[] nonce) &&
            SymmetricKeyHelper.TryGetJsonBase64(publicParametersJson, "tag", out byte[] tag))
        {
            byte[] plain = new byte[cipherBytes.Length];
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(nonce, cipherBytes, tag, plain);

            return new CryptoOperationResult
            {
                AlgorithmCode = Info.Code,
                OutputBytes = plain,
                SecretKeyBase64 = secretKeyBase64,
                PublicParametersJson = publicParametersJson,
                Summary = $"AES-256-GCM autenticado y descifrado ({plain.Length} bytes)."
            };
        }

        // Fallback: Formato empaquetado externo CentroCiberseguridad.Web en datos.enc
        if (cipherBytes.Length < 28)
            throw new CryptographicException("Datos cifrados AES-GCM insuficientes para extraer Nonce y Tag.");

        using var aesFallback = new AesGcm(key, 16);

        // Layout A: [12B nonce][16B tag][ciphertext]
        try
        {
            byte[] nA = cipherBytes[..12];
            byte[] tA = cipherBytes[12..28];
            byte[] cA = cipherBytes[28..];
            byte[] plainA = new byte[cA.Length];
            aesFallback.Decrypt(nA, cA, tA, plainA);

            return new CryptoOperationResult
            {
                AlgorithmCode = Info.Code,
                OutputBytes = plainA,
                SecretKeyBase64 = secretKeyBase64,
                PublicParametersJson = publicParametersJson,
                Summary = $"AES-256-GCM (formato externo nonce+tag+cipher) descifrado ({plainA.Length} bytes)."
            };
        }
        catch
        {
            // Layout B: [12B nonce][ciphertext][16B tag]
            byte[] nB = cipherBytes[..12];
            byte[] cB = cipherBytes[12..^16];
            byte[] tB = cipherBytes[^16..];
            byte[] plainB = new byte[cB.Length];
            aesFallback.Decrypt(nB, cB, tB, plainB);

            return new CryptoOperationResult
            {
                AlgorithmCode = Info.Code,
                OutputBytes = plainB,
                SecretKeyBase64 = secretKeyBase64,
                PublicParametersJson = publicParametersJson,
                Summary = $"AES-256-GCM (formato externo nonce+cipher+tag) descifrado ({plainB.Length} bytes)."
            };
        }
    }
}

/// <summary>2. DES — DES 56-bit</summary>
public sealed class DesStrategy : ICryptoStrategy
{
    public CryptoAlgorithmInfo Info { get; } = new()
    {
        Code = "DES",
        DisplayName = "DES 56-bit",
        Category = "Simétrico Clásico",
        Description = "Data Encryption Standard con llave efectiva de 56 bits (bloque 64-bit, CBC/PKCS7)."
    };

    public CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase = null)
    {
        using var des = DES.Create();
        des.Mode = CipherMode.CBC;
        des.Padding = PaddingMode.PKCS7;
        if (!string.IsNullOrWhiteSpace(optionalPassphrase))
            des.Key = SHA256.HashData(Encoding.UTF8.GetBytes(optionalPassphrase))[..8];
        else
            des.GenerateKey();
        des.GenerateIV();

        byte[] cipher = des.EncryptCbc(plainBytes, des.IV, PaddingMode.PKCS7);
        string pubJson = JsonSerializer.Serialize(new
        {
            mode = "DES-CBC-PKCS7",
            iv = Convert.ToBase64String(des.IV)
        });

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = cipher,
            SecretKeyBase64 = Convert.ToBase64String(des.Key),
            PublicParametersJson = pubJson,
            Summary = $"DES 56-bit cifrado ({cipher.Length} bytes)."
        };
    }

    public CryptoOperationResult Decrypt(byte[] cipherBytes, string secretKeyBase64, string publicParametersJson)
    {
        using var des = DES.Create();
        des.Key = SymmetricKeyHelper.ResolveKey(secretKeyBase64, 8);

        byte[] iv;
        byte[] actualCipher;

        if (SymmetricKeyHelper.TryGetJsonBase64(publicParametersJson, "iv", out byte[] jsonIv))
        {
            iv = jsonIv;
            actualCipher = cipherBytes;
        }
        else
        {
            if (cipherBytes.Length <= 8)
                throw new CryptographicException("Payload DES empaquetado demasiado corto para extraer IV.");
            iv = cipherBytes[..8];
            actualCipher = cipherBytes[8..];
        }

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
}

/// <summary>3. TRIPLEDES — Triple DES / 3DES</summary>
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
        if (!string.IsNullOrWhiteSpace(optionalPassphrase))
            tdes.Key = SHA256.HashData(Encoding.UTF8.GetBytes(optionalPassphrase))[..24];
        else
            tdes.GenerateKey();
        tdes.GenerateIV();

        byte[] cipher = tdes.EncryptCbc(plainBytes, tdes.IV, PaddingMode.PKCS7);
        string pubJson = JsonSerializer.Serialize(new
        {
            mode = "3DES-EDE-CBC",
            iv = Convert.ToBase64String(tdes.IV)
        });

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = cipher,
            SecretKeyBase64 = Convert.ToBase64String(tdes.Key),
            PublicParametersJson = pubJson,
            Summary = $"Triple DES cifrado ({cipher.Length} bytes)."
        };
    }

    public CryptoOperationResult Decrypt(byte[] cipherBytes, string secretKeyBase64, string publicParametersJson)
    {
        using var tdes = TripleDES.Create();
        tdes.Key = SymmetricKeyHelper.ResolveKey(secretKeyBase64, 24);

        byte[] iv;
        byte[] actualCipher;

        if (SymmetricKeyHelper.TryGetJsonBase64(publicParametersJson, "iv", out byte[] jsonIv))
        {
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
}

/// <summary>4. CHACHA20 — ChaCha20-Poly1305 (nativo o RFC 8439 gestionado en Windows)</summary>
public sealed class ChaCha20Strategy : ICryptoStrategy
{
    public CryptoAlgorithmInfo Info { get; } = new()
    {
        Code = "CHACHA20",
        DisplayName = "ChaCha20-Poly1305",
        Category = "Simétrico Stream AEAD",
        Description = "Cifrado de flujo ChaCha20 (256-bit) con autenticación MAC (RFC 8439)."
    };

    public CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase = null)
    {
        byte[] key = string.IsNullOrWhiteSpace(optionalPassphrase)
            ? RandomNumberGenerator.GetBytes(32)
            : SHA256.HashData(Encoding.UTF8.GetBytes(optionalPassphrase));
        byte[] nonce = RandomNumberGenerator.GetBytes(12);

        byte[] cipher = new byte[plainBytes.Length];
        byte[] tag = new byte[16];
        string engine;

        if (ChaCha20Poly1305.IsSupported)
        {
            using var cc = new ChaCha20Poly1305(key);
            cc.Encrypt(nonce, plainBytes, cipher, tag);
            engine = "Native-ChaCha20Poly1305";
        }
        else
        {
            cipher = ChaCha20Transform(key, nonce, 1, plainBytes);
            tag = ComputeAuthTag(key, nonce, cipher);
            engine = "RFC8439-ChaCha20-Managed";
        }

        string pubJson = JsonSerializer.Serialize(new
        {
            mode = engine,
            nonce = Convert.ToBase64String(nonce),
            tag = Convert.ToBase64String(tag)
        });

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = cipher,
            SecretKeyBase64 = Convert.ToBase64String(key),
            PublicParametersJson = pubJson,
            Summary = $"ChaCha20-Poly1305 ({engine}) cifrado ({cipher.Length} bytes)."
        };
    }

    public CryptoOperationResult Decrypt(byte[] cipherBytes, string secretKeyBase64, string publicParametersJson)
    {
        byte[] key = SymmetricKeyHelper.ResolveKey(secretKeyBase64, 32);

        if (SymmetricKeyHelper.TryGetJsonBase64(publicParametersJson, "nonce", out byte[] nonce) &&
            SymmetricKeyHelper.TryGetJsonBase64(publicParametersJson, "tag", out byte[] tag))
        {
            string mode = SymmetricKeyHelper.TryGetJsonString(publicParametersJson, "mode");
            byte[] plain = DecryptWithNonceAndTag(key, nonce, tag, cipherBytes, mode);

            return new CryptoOperationResult
            {
                AlgorithmCode = Info.Code,
                OutputBytes = plain,
                SecretKeyBase64 = secretKeyBase64,
                PublicParametersJson = publicParametersJson,
                Summary = $"ChaCha20-Poly1305 autenticado y descifrado ({plain.Length} bytes)."
            };
        }

        // Fallback formato empaquetado externo en datos.enc
        if (cipherBytes.Length < 28)
            throw new CryptographicException("Datos cifrados ChaCha20 insuficientes para extraer Nonce y Tag.");

        try
        {
            // Layout A: [12B nonce][16B tag][ciphertext]
            byte[] nA = cipherBytes[..12];
            byte[] tA = cipherBytes[12..28];
            byte[] cA = cipherBytes[28..];
            byte[] plainA = DecryptWithNonceAndTag(key, nA, tA, cA, "Native-ChaCha20Poly1305");
            return new CryptoOperationResult
            {
                AlgorithmCode = Info.Code,
                OutputBytes = plainA,
                SecretKeyBase64 = secretKeyBase64,
                PublicParametersJson = publicParametersJson,
                Summary = $"ChaCha20-Poly1305 (formato externo nonce+tag+cipher) descifrado ({plainA.Length} bytes)."
            };
        }
        catch
        {
            // Layout B: [12B nonce][ciphertext][16B tag]
            byte[] nB = cipherBytes[..12];
            byte[] cB = cipherBytes[12..^16];
            byte[] tB = cipherBytes[^16..];
            byte[] plainB = DecryptWithNonceAndTag(key, nB, tB, cB, "Native-ChaCha20Poly1305");
            return new CryptoOperationResult
            {
                AlgorithmCode = Info.Code,
                OutputBytes = plainB,
                SecretKeyBase64 = secretKeyBase64,
                PublicParametersJson = publicParametersJson,
                Summary = $"ChaCha20-Poly1305 (formato externo nonce+cipher+tag) descifrado ({plainB.Length} bytes)."
            };
        }
    }

    private static byte[] DecryptWithNonceAndTag(byte[] key, byte[] nonce, byte[] tag, byte[] cipherBytes, string mode)
    {
        if (ChaCha20Poly1305.IsSupported && mode != "RFC8439-ChaCha20-Managed")
        {
            try
            {
                byte[] plain = new byte[cipherBytes.Length];
                using var cc = new ChaCha20Poly1305(key);
                cc.Decrypt(nonce, cipherBytes, tag, plain);
                return plain;
            }
            catch when (string.IsNullOrEmpty(mode))
            {
                // Si no especificó modo, probar también el motor gestionado
            }
        }

        byte[] expected = ComputeAuthTag(key, nonce, cipherBytes);
        if (!CryptographicOperations.FixedTimeEquals(expected, tag))
            throw new CryptographicException("Tag de autenticación ChaCha20 inválido.");
        return ChaCha20Transform(key, nonce, 1, cipherBytes);
    }

    private static byte[] ComputeAuthTag(byte[] key, byte[] nonce, byte[] cipher)
    {
        byte[] polyKey = ChaCha20Block(key, 0, nonce)[..32];
        using var hmac = new HMACSHA256(polyKey);
        byte[] input = new byte[nonce.Length + cipher.Length];
        Buffer.BlockCopy(nonce, 0, input, 0, nonce.Length);
        Buffer.BlockCopy(cipher, 0, input, nonce.Length, cipher.Length);
        return hmac.ComputeHash(input)[..16];
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
