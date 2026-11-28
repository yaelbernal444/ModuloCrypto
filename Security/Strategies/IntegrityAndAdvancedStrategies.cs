using System.Buffers.Binary;
using System.Drawing;
using System.Drawing.Imaging;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ModuloCrypto.Security.Strategies;

/// <summary>11. LSBSTEGO — Esteganografía LSB en PNG/BMP</summary>
public sealed class LsbStegoStrategy : ICryptoStrategy
{
    public CryptoAlgorithmInfo Info { get; } = new()
    {
        Code = "LSBSTEGO",
        DisplayName = "Esteganografía LSB en PNG/BMP",
        Category = "Esteganografía",
        Description = "Oculta la carga útil en los bits menos significativos (LSB) de píxeles RGB de una imagen PNG."
    };

    public CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase = null)
    {
        // Cabecera [4 bytes Magic "LSBC"][4 bytes longitud][payload]
        byte[] packet = new byte[8 + plainBytes.Length];
        Encoding.ASCII.GetBytes("LSBC").CopyTo(packet, 0);
        BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(4, 4), plainBytes.Length);
        Buffer.BlockCopy(plainBytes, 0, packet, 8, plainBytes.Length);

        int totalBits = packet.Length * 8;
        int pixelsNeeded = (totalBits + 2) / 3;
        int side = Math.Max(128, (int)Math.Ceiling(Math.Sqrt(pixelsNeeded)) + 8);

        using var bmp = new Bitmap(side, side, PixelFormat.Format24bppRgb);
        // Generar fondo holográfico oscuro espacial como portador visual
        for (int y = 0; y < side; y++)
        {
            for (int x = 0; x < side; x++)
            {
                int r = 14 + (int)(25 * Math.Sin(x * 0.04) * Math.Cos(y * 0.04) + 25);
                int g = 10 + (int)(30 * Math.Sin((x + y) * 0.03) + 30);
                int b = 38 + (int)(70 * Math.Cos((x - y) * 0.025) + 70);
                bmp.SetPixel(x, y, Color.FromArgb(Math.Clamp(r, 0, 255), Math.Clamp(g, 0, 255), Math.Clamp(b, 0, 255)));
            }
        }

        int bitIndex = 0;
        for (int y = 0; y < side && bitIndex < totalBits; y++)
        {
            for (int x = 0; x < side && bitIndex < totalBits; x++)
            {
                Color c = bmp.GetPixel(x, y);
                int r = c.R, g = c.G, b = c.B;

                if (bitIndex < totalBits) { r = (r & 0xFE) | GetBit(packet, bitIndex++); }
                if (bitIndex < totalBits) { g = (g & 0xFE) | GetBit(packet, bitIndex++); }
                if (bitIndex < totalBits) { b = (b & 0xFE) | GetBit(packet, bitIndex++); }

                bmp.SetPixel(x, y, Color.FromArgb(r, g, b));
            }
        }

        using var ms = new MemoryStream();
        bmp.Save(ms, ImageFormat.Png);
        byte[] pngBytes = ms.ToArray();

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = pngBytes,
            SecretKeyBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes($"LSB-RGB-{side}x{side}")),
            PublicParametersJson = JsonSerializer.Serialize(new
            {
                carrierFormat = "PNG-24bpp",
                dimensions = $"{side}x{side}",
                embeddedBytes = plainBytes.Length,
                channels = "R,G,B (1-bit LSB)"
            }),
            OutputExtensionOverride = ".png",
            Summary = $"LSBSTEGO incrustado en imagen PNG {side}x{side} ({plainBytes.Length} bytes ocultos)."
        };
    }

    public CryptoOperationResult Decrypt(byte[] cipherBytes, string secretKeyBase64, string publicParametersJson)
    {
        using var ms = new MemoryStream(cipherBytes);
        using var bmp = new Bitmap(ms);

        // Extraer todos los bits LSB suficientes para cabecera y payload
        byte[] header = ExtractBytes(bmp, 0, 8);
        string magic = Encoding.ASCII.GetString(header, 0, 4);
        if (magic != "LSBC")
            throw new CryptographicException("La imagen no contiene cabecera válida LSBSTEGO (LSBC).");

        int payloadLen = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(4, 4));
        if (payloadLen < 0 || payloadLen > 50_000_000)
            throw new CryptographicException("Longitud de carga esteganográfica fuera de rango.");

        byte[] full = ExtractBytes(bmp, 0, 8 + payloadLen);
        byte[] payload = full[8..];

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = payload,
            SecretKeyBase64 = secretKeyBase64,
            PublicParametersJson = publicParametersJson,
            Summary = $"LSBSTEGO extraído correctamente desde PNG ({payload.Length} bytes)."
        };
    }

    private static int GetBit(byte[] data, int bitIndex)
    {
        int byteIdx = bitIndex / 8;
        int bitOffset = 7 - (bitIndex % 8);
        return (data[byteIdx] >> bitOffset) & 1;
    }

    private static byte[] ExtractBytes(Bitmap bmp, int startBit, int byteCount)
    {
        byte[] result = new byte[byteCount];
        int totalBits = byteCount * 8;
        int bitIndex = 0;

        for (int y = 0; y < bmp.Height && bitIndex < totalBits; y++)
        {
            for (int x = 0; x < bmp.Width && bitIndex < totalBits; x++)
            {
                Color c = bmp.GetPixel(x, y);
                int[] channels = { c.R & 1, c.G & 1, c.B & 1 };
                foreach (int bit in channels)
                {
                    if (bitIndex >= totalBits) break;
                    if (bitIndex >= startBit)
                    {
                        int rel = bitIndex - startBit;
                        result[rel / 8] |= (byte)(bit << (7 - (rel % 8)));
                    }
                    bitIndex++;
                }
            }
        }
        return result;
    }
}

/// <summary>13. MILLERRABIN — Miller-Rabin Modular</summary>
public sealed class MillerRabinStrategy : ICryptoStrategy
{
    public CryptoAlgorithmInfo Info { get; } = new()
    {
        Code = "MILLERRABIN",
        DisplayName = "Miller-Rabin Modular",
        Category = "Primalidad / Modular",
        Description = "Generación de primos verificados con test probabilístico Miller-Rabin (k=20) y exponenciación modular."
    };

    public CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase = null)
    {
        BigInteger p = GenerateProbablePrime(32);
        BigInteger q = GenerateProbablePrime(32);
        while (q == p) q = GenerateProbablePrime(32);

        BigInteger n = p * q;
        BigInteger phi = (p - 1) * (q - 1);
        BigInteger e = 65537;
        while (BigInteger.GreatestCommonDivisor(e, phi) != 1) e += 2;
        BigInteger d = ModInverse(e, phi);

        // Cifrado modular bloque de 4 bytes -> 8 bytes (UInt64)
        byte[] padded = new byte[4 + plainBytes.Length];
        BinaryPrimitives.WriteInt32BigEndian(padded.AsSpan(0, 4), plainBytes.Length);
        Buffer.BlockCopy(plainBytes, 0, padded, 4, plainBytes.Length);

        int blocks = (padded.Length + 3) / 4;
        byte[] cipher = new byte[blocks * 8];
        for (int i = 0; i < blocks; i++)
        {
            uint m = 0;
            for (int j = 0; j < 4; j++)
            {
                int idx = i * 4 + j;
                m = (m << 8) | (idx < padded.Length ? padded[idx] : (byte)0);
            }
            BigInteger c = BigInteger.ModPow(m, e, n);
            BinaryPrimitives.WriteUInt64BigEndian(cipher.AsSpan(i * 8, 8), (ulong)c);
        }

        string pubJson = JsonSerializer.Serialize(new
        {
            roundsMillerRabin = 20,
            modulusN = n.ToString(),
            publicE = e.ToString(),
            primeBits = 32
        });

        string secretJson = JsonSerializer.Serialize(new { d = d.ToString(), n = n.ToString() });

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = cipher,
            SecretKeyBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(secretJson)),
            PublicParametersJson = pubJson,
            Summary = $"Miller-Rabin primos (p,q) validados -> cifrado modular ({cipher.Length} bytes)."
        };
    }

    public CryptoOperationResult Decrypt(byte[] cipherBytes, string secretKeyBase64, string publicParametersJson)
    {
        string trimmedSec = (secretKeyBase64 ?? string.Empty).Trim();
        string secretJson;
        if (trimmedSec.StartsWith('{'))
        {
            secretJson = trimmedSec;
        }
        else if (KeyInputParser.TryDecodeFlexibleBase64(trimmedSec, out byte[] rawSec))
        {
            secretJson = Encoding.UTF8.GetString(rawSec);
        }
        else
        {
            throw new CryptographicException("Llave privada Miller-Rabin inválida (se esperaba Base64 o JSON con {d, n}). Si proviene de otro nodo, delega el descifrado al dueño.");
        }

        using var doc = JsonDocument.Parse(secretJson);
        if (!KeyInputParser.TryGetJsonString(doc.RootElement, out string dStr, "d") ||
            !KeyInputParser.TryGetJsonString(doc.RootElement, out string nStr, "n"))
        {
            throw new CryptographicException("Parámetros d/n faltantes en llave Miller-Rabin.");
        }

        BigInteger d = BigInteger.Parse(dStr);
        BigInteger n = BigInteger.Parse(nStr);

        if (cipherBytes.Length < 8 || cipherBytes.Length % 8 != 0)
            throw new CryptographicException("Longitud de payload cifrado Miller-Rabin inválida (múltiplo de 8 bytes requerido).");

        int blocks = cipherBytes.Length / 8;
        byte[] padded = new byte[blocks * 4];
        for (int i = 0; i < blocks; i++)
        {
            ulong cVal = BinaryPrimitives.ReadUInt64BigEndian(cipherBytes.AsSpan(i * 8, 8));
            BigInteger m = BigInteger.ModPow(cVal, d, n);
            uint m32 = (uint)m;
            BinaryPrimitives.WriteUInt32BigEndian(padded.AsSpan(i * 4, 4), m32);
        }

        if (padded.Length < 4)
            throw new CryptographicException("Bloque descifrado Miller-Rabin incompleto.");

        int origLen = BinaryPrimitives.ReadInt32BigEndian(padded.AsSpan(0, 4));
        if (origLen < 0 || 4 + origLen > padded.Length)
            throw new CryptographicException("Longitud original inválida tras descifrado Miller-Rabin (llave incorrecta o formato incompatible).");

        byte[] plain = padded[4..(4 + origLen)];

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = plain,
            SecretKeyBase64 = secretKeyBase64 ?? string.Empty,
            PublicParametersJson = publicParametersJson,
            Summary = $"Miller-Rabin exponenciación modular inversa completada ({plain.Length} bytes)."
        };
    }

    private static BigInteger GenerateProbablePrime(int bits)
    {
        byte[] buf = new byte[(bits + 7) / 8];
        while (true)
        {
            RandomNumberGenerator.Fill(buf);
            buf[^1] |= 0x80; // asegura bit más significativo
            buf[0] |= 0x01;  // impar
            var candidate = new BigInteger(buf, isUnsigned: true, isBigEndian: false);
            if (candidate > 65537 && IsProbablePrime(candidate, 20))
                return candidate;
        }
    }

    private static bool IsProbablePrime(BigInteger n, int rounds)
    {
        if (n < 2) return false;
        if (n == 2 || n == 3) return true;
        if (n.IsEven) return false;

        BigInteger d = n - 1;
        int s = 0;
        while (d.IsEven) { d >>= 1; s++; }

        for (int i = 0; i < rounds; i++)
        {
            BigInteger a = 2 + (RandomNumberGenerator.GetInt32(0, int.MaxValue) % (n - 3));
            BigInteger x = BigInteger.ModPow(a, d, n);
            if (x == 1 || x == n - 1) continue;

            bool composite = true;
            for (int r = 1; r < s; r++)
            {
                x = BigInteger.ModPow(x, 2, n);
                if (x == n - 1) { composite = false; break; }
            }
            if (composite) return false;
        }
        return true;
    }

    private static BigInteger ModInverse(BigInteger a, BigInteger m)
    {
        BigInteger t = 0, newT = 1, r = m, newR = a;
        while (newR != 0)
        {
            BigInteger q = r / newR;
            (t, newT) = (newT, t - q * newT);
            (r, newR) = (newR, r - q * newR);
        }
        if (t < 0) t += m;
        return t;
    }
}

/// <summary>15. HASHSHA — SHA-256 / SHA-512</summary>
public sealed class HashShaStrategy : ICryptoStrategy
{
    public CryptoAlgorithmInfo Info { get; } = new()
    {
        Code = "HASHSHA",
        DisplayName = "SHA-256 / SHA-512",
        Category = "Integridad / Hash",
        Description = "Resumen criptográfico dual SHA-256 y SHA-512 (unidireccional con verificación de integridad).",
        IsReversible = false
    };

    public CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase = null)
    {
        byte[] sha256 = SHA256.HashData(plainBytes);
        byte[] sha512 = SHA512.HashData(plainBytes);

        string report = $"SHA-256: {Convert.ToHexString(sha256)}\r\nSHA-512: {Convert.ToHexString(sha512)}";
        byte[] reportBytes = Encoding.UTF8.GetBytes(report);

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = reportBytes,
            SecretKeyBase64 = Convert.ToBase64String(sha256),
            PublicParametersJson = JsonSerializer.Serialize(new
            {
                sha256 = Convert.ToHexString(sha256),
                sha512 = Convert.ToHexString(sha512),
                inputLength = plainBytes.Length
            }),
            Summary = $"Resumen dual SHA-256 / SHA-512 calculado ({plainBytes.Length} bytes)."
        };
    }

    public CryptoOperationResult Decrypt(byte[] cipherBytes, string secretKeyBase64, string publicParametersJson)
    {
        JsonDocument? doc = null;
        try
        {
            if (!string.IsNullOrWhiteSpace(publicParametersJson))
                doc = JsonDocument.Parse(publicParametersJson);

            if (doc != null &&
                KeyInputParser.TryGetJsonString(doc.RootElement, out string digestHex, "digestHex", "digest", "hashHex") &&
                !string.IsNullOrWhiteSpace(digestHex))
            {
                string hashAlg = KeyInputParser.TryGetJsonString(doc.RootElement, out string ha, "hashAlgorithm", "algorithm") &&
                                 !string.IsNullOrWhiteSpace(ha)
                    ? ha.Trim().ToUpperInvariant()
                    : "SHA-256";

                byte[] actualHash = hashAlg.Contains("512", StringComparison.OrdinalIgnoreCase)
                    ? SHA512.HashData(cipherBytes)
                    : SHA256.HashData(cipherBytes);

                string actualHex = Convert.ToHexString(actualHash).ToLowerInvariant();
                string expectedHex = digestHex.Trim().ToLowerInvariant();
                bool isValid = expectedHex.Length == actualHex.Length &&
                               CryptographicOperations.FixedTimeEquals(
                                   Encoding.ASCII.GetBytes(actualHex),
                                   Encoding.ASCII.GetBytes(expectedHex));

                return new CryptoOperationResult
                {
                    AlgorithmCode = Info.Code,
                    Success = isValid,
                    OutputBytes = cipherBytes,
                    SecretKeyBase64 = secretKeyBase64,
                    PublicParametersJson = publicParametersJson,
                    Summary = isValid
                        ? $"VERIFICACIÓN VÁLIDA ({hashAlg}) — integridad verificada sobre {cipherBytes.Length} bytes ({actualHex[..Math.Min(16, actualHex.Length)]}...)."
                        : $"VERIFICACIÓN INVÁLIDA ({hashAlg}) — esperado={expectedHex[..Math.Min(16, expectedHex.Length)]}..., calculado={actualHex[..Math.Min(16, actualHex.Length)]}...."
                };
            }

            if (doc != null &&
                KeyInputParser.TryGetJsonString(doc.RootElement, out string expected256, "sha256") &&
                !string.IsNullOrWhiteSpace(expected256))
            {
                string actual256 = Convert.ToHexString(SHA256.HashData(cipherBytes)).ToLowerInvariant();
                string clean256 = expected256.Trim().ToLowerInvariant();
                bool valid = clean256.Length == actual256.Length &&
                             CryptographicOperations.FixedTimeEquals(
                                 Encoding.ASCII.GetBytes(actual256),
                                 Encoding.ASCII.GetBytes(clean256));

                if (valid && KeyInputParser.TryGetJsonString(doc.RootElement, out string expected512, "sha512") && !string.IsNullOrWhiteSpace(expected512))
                {
                    string actual512 = Convert.ToHexString(SHA512.HashData(cipherBytes)).ToLowerInvariant();
                    string clean512 = expected512.Trim().ToLowerInvariant();
                    valid = clean512.Length == actual512.Length &&
                            CryptographicOperations.FixedTimeEquals(
                                Encoding.ASCII.GetBytes(actual512),
                                Encoding.ASCII.GetBytes(clean512));
                }

                return new CryptoOperationResult
                {
                    AlgorithmCode = Info.Code,
                    Success = valid,
                    OutputBytes = cipherBytes,
                    SecretKeyBase64 = secretKeyBase64,
                    PublicParametersJson = publicParametersJson,
                    Summary = valid
                        ? $"VERIFICACIÓN VÁLIDA (SHA-256/SHA-512) — integridad confirmada ({cipherBytes.Length} bytes)."
                        : $"VERIFICACIÓN INVÁLIDA — el resumen SHA-256/SHA-512 no coincide."
                };
            }

            return new CryptoOperationResult
            {
                AlgorithmCode = Info.Code,
                Success = false,
                OutputBytes = cipherBytes,
                SecretKeyBase64 = secretKeyBase64,
                PublicParametersJson = publicParametersJson,
                Summary = "VERIFICACIÓN INVÁLIDA — no se encontró digestHex ni sha256 en publicParameters."
            };
        }
        finally
        {
            doc?.Dispose();
        }
    }
}

/// <summary>16. HMACSHA256 — HMAC-SHA256</summary>
public sealed class HmacSha256Strategy : ICryptoStrategy
{
    public CryptoAlgorithmInfo Info { get; } = new()
    {
        Code = "HMACSHA256",
        DisplayName = "HMAC-SHA256",
        Category = "Autenticación MAC",
        Description = "Código de autenticación de mensajes con clave secreta HMAC-SHA256 + sobre íntegro."
    };

    public CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase = null)
    {
        byte[] key = string.IsNullOrWhiteSpace(optionalPassphrase)
            ? RandomNumberGenerator.GetBytes(32)
            : SHA256.HashData(Encoding.UTF8.GetBytes(optionalPassphrase));

        using var hmac = new HMACSHA256(key);
        byte[] mac = hmac.ComputeHash(plainBytes);

        // Sobre local: [32 bytes MAC][payload]
        byte[] envelope = new byte[mac.Length + plainBytes.Length];
        Buffer.BlockCopy(mac, 0, envelope, 0, mac.Length);
        Buffer.BlockCopy(plainBytes, 0, envelope, mac.Length, plainBytes.Length);

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = envelope,
            SecretKeyBase64 = Convert.ToBase64String(key),
            PublicParametersJson = JsonSerializer.Serialize(new
            {
                macTagHex = Convert.ToHexString(mac),
                macBits = 256,
                layout = "MAC32_PAYLOAD"
            }),
            Summary = $"HMAC-SHA256 autenticado (MAC={Convert.ToHexString(mac)[..16]}...)."
        };
    }

    public CryptoOperationResult Decrypt(byte[] cipherBytes, string secretKeyBase64, string publicParametersJson)
    {
        var candidateKeys = KeyInputParser.BuildKeyCandidates(secretKeyBase64);
        if (candidateKeys.Count == 0)
            throw new CryptographicException("Llave secreta HMAC vacía o con formato inválido.");

        string? macHex = null;
        string? layout = null;
        string macAlg = "HMAC-SHA256";
        if (!string.IsNullOrWhiteSpace(publicParametersJson))
        {
            try
            {
                using var doc = JsonDocument.Parse(publicParametersJson);
                if (KeyInputParser.TryGetJsonString(doc.RootElement, out string mh, "macHex") && !string.IsNullOrWhiteSpace(mh))
                    macHex = mh.Trim();
                if (KeyInputParser.TryGetJsonString(doc.RootElement, out string l, "layout") && !string.IsNullOrWhiteSpace(l))
                    layout = l.Trim();
                if (KeyInputParser.TryGetJsonString(doc.RootElement, out string ma, "macAlgorithm", "algorithm") && !string.IsNullOrWhiteSpace(ma))
                    macAlg = ma.Trim().ToUpperInvariant();
            }
            catch { }
        }

        // Modo v2.0 estándar: publicParameters contiene macHex sin layout MAC32_PAYLOAD y cipherBytes es el archivo íntegro sin prefijo de 32 bytes
        if (!string.IsNullOrWhiteSpace(macHex) &&
            !string.Equals(layout, "MAC32_PAYLOAD", StringComparison.OrdinalIgnoreCase))
        {
            bool looksLikeLegacyPrefixed =
                KeyInputParser.TryDecodeHex(macHex, out byte[] expectedMacBytes) &&
                expectedMacBytes.Length == 32 &&
                cipherBytes.Length >= 32 &&
                cipherBytes.AsSpan(0, 32).SequenceEqual(expectedMacBytes);

            if (!looksLikeLegacyPrefixed)
            {
                bool isSha512 = macAlg.Contains("512", StringComparison.OrdinalIgnoreCase);
                bool matched = false;

                if (KeyInputParser.TryDecodeHex(macHex, out byte[] expBytes))
                {
                    foreach (byte[] keyCand in candidateKeys)
                    {
                        byte[] computed = isSha512
                            ? HMACSHA512.HashData(keyCand, cipherBytes)
                            : HMACSHA256.HashData(keyCand, cipherBytes);
                        if (computed.Length == expBytes.Length &&
                            CryptographicOperations.FixedTimeEquals(computed, expBytes))
                        {
                            matched = true;
                            break;
                        }
                    }
                }

                return new CryptoOperationResult
                {
                    AlgorithmCode = Info.Code,
                    Success = matched,
                    OutputBytes = cipherBytes,
                    SecretKeyBase64 = secretKeyBase64,
                    PublicParametersJson = publicParametersJson,
                    Summary = matched
                        ? $"VERIFICACIÓN VÁLIDA ({macAlg}) — código de autenticación HMAC confirmado ({cipherBytes.Length} bytes)."
                        : $"VERIFICACIÓN INVÁLIDA ({macAlg}) — llave incorrecta o mensaje alterado (macHex={macHex[..Math.Min(16, macHex.Length)]}...)."
                };
            }
        }

        // Modo local / legado: sobre [32B MAC][payload]
        if (cipherBytes.Length < 32)
            throw new CryptographicException("Sobre HMAC inválido: tamaño menor a 32 bytes de etiqueta MAC.");

        byte[] embeddedMac = cipherBytes[..32];
        byte[] payload = cipherBytes[32..];

        foreach (byte[] keyCand in candidateKeys)
        {
            byte[] computed = HMACSHA256.HashData(keyCand, payload);
            if (CryptographicOperations.FixedTimeEquals(embeddedMac, computed))
            {
                return new CryptoOperationResult
                {
                    AlgorithmCode = Info.Code,
                    Success = true,
                    OutputBytes = payload,
                    SecretKeyBase64 = secretKeyBase64,
                    PublicParametersJson = publicParametersJson,
                    Summary = $"HMAC-SHA256 VÁLIDO — payload auténtico recuperado ({payload.Length} bytes)."
                };
            }
        }

        throw new CryptographicException("HMAC-SHA256 inválido: la llave secreta no coincide o el mensaje fue alterado.");
    }
}

/// <summary>18. QUANTUMPQC — Simulación QKD BB84 / LWE</summary>
public sealed class QuantumPqcStrategy : ICryptoStrategy
{
    private const int Q = 3329; // Módulo Kyber/ML-KEM (LWE)

    public CryptoAlgorithmInfo Info { get; } = new()
    {
        Code = "QUANTUMPQC",
        DisplayName = "Simulación QKD BB84 / LWE",
        Category = "Post-Cuántico / QKD",
        Description = "Distribución cuántica BB84 (bases rectilínea/diagonal) + cifrado por retículos LWE mod 3329."
    };

    public CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase = null)
    {
        // 1. Simulación QKD BB84: 256 fotones -> conciliación de bases -> llave cuántica
        int qubits = 256;
        var siftedBits = new List<byte>();
        for (int i = 0; i < qubits; i++)
        {
            int aliceBasis = RandomNumberGenerator.GetInt32(0, 2);
            int bobBasis = RandomNumberGenerator.GetInt32(0, 2);
            int bit = RandomNumberGenerator.GetInt32(0, 2);
            if (aliceBasis == bobBasis)
                siftedBits.Add((byte)bit);
        }

        byte[] bb84Key = SHA256.HashData(siftedBits.ToArray());

        // 2. Retículo LWE simplificado: cada byte se codifica en vector mod Q con ruido gaussiano acotado
        int s = (BinaryPrimitives.ReadUInt16LittleEndian(bb84Key) % 41) + 3;
        byte[] cipher = new byte[plainBytes.Length * 4]; // (u, v) como 2 UInt16 por byte

        for (int i = 0; i < plainBytes.Length; i++)
        {
            int u = RandomNumberGenerator.GetInt32(1, Q - 1);
            int noise = RandomNumberGenerator.GetInt32(-2, 3); // pequeño error controlado
            // Escalamos byte [0..255] -> factor 12 (máx 3060 < 3329), tolerando ruido [-2..2]
            int v = ((u * s) + (plainBytes[i] * 12) + noise) % Q;
            if (v < 0) v += Q;

            BinaryPrimitives.WriteUInt16BigEndian(cipher.AsSpan(i * 4, 2), (ushort)u);
            BinaryPrimitives.WriteUInt16BigEndian(cipher.AsSpan(i * 4 + 2, 2), (ushort)v);
        }

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = cipher,
            SecretKeyBase64 = Convert.ToBase64String(bb84Key),
            PublicParametersJson = JsonSerializer.Serialize(new
            {
                protocol = "BB84-QKD + LWE-Lattice",
                modulusQ = Q,
                photonsSent = qubits,
                siftedBits = siftedBits.Count,
                qber = "0.00% (Canal Seguro)"
            }),
            Summary = $"QUANTUMPQC (BB84 {siftedBits.Count} bits + LWE mod {Q}) cifrado ({cipher.Length} bytes)."
        };
    }

    public CryptoOperationResult Decrypt(byte[] cipherBytes, string secretKeyBase64, string publicParametersJson)
    {
        byte[] bb84Key = KeyInputParser.ParseRawOrTextKey(secretKeyBase64, preferBase64WithoutPadding: true);
        if (bb84Key.Length < 2)
            throw new CryptographicException("Llave cuántica BB84/LWE inválida o menor a 2 bytes.");

        int s = (BinaryPrimitives.ReadUInt16LittleEndian(bb84Key) % 41) + 3;

        int count = cipherBytes.Length / 4;
        byte[] plain = new byte[count];
        for (int i = 0; i < count; i++)
        {
            int u = BinaryPrimitives.ReadUInt16BigEndian(cipherBytes.AsSpan(i * 4, 2));
            int v = BinaryPrimitives.ReadUInt16BigEndian(cipherBytes.AsSpan(i * 4 + 2, 2));
            int diff = (v - (u * s) % Q + Q) % Q;
            int recovered = (int)Math.Round(diff / 12.0);
            plain[i] = (byte)Math.Clamp(recovered, 0, 255);
        }

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = plain,
            SecretKeyBase64 = secretKeyBase64,
            PublicParametersJson = publicParametersJson,
            Summary = $"QUANTUMPQC LWE ruido eliminado y payload recuperado ({plain.Length} bytes)."
        };
    }
}

/// <summary>19. DFTSPECTRAL — Transformada Discreta de Fourier</summary>
public sealed class DftSpectralStrategy : ICryptoStrategy
{
    public CryptoAlgorithmInfo Info { get; } = new()
    {
        Code = "DFTSPECTRAL",
        DisplayName = "Transformada Discreta de Fourier",
        Category = "Espectral / Señales",
        Description = "Modulación de fase en el dominio de frecuencia mediante DFT/IDFT por bloques."
    };

    public CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase = null)
    {
        const int blockSize = 16;
        byte[] phaseSeed = RandomNumberGenerator.GetBytes(blockSize);

        int blocks = Math.Max(1, (plainBytes.Length + blockSize - 1) / blockSize);
        // Guardamos [4 bytes longitud original] + [blocks * blockSize * 2 doubles (Real, Imag)]
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);
        bw.Write(plainBytes.Length);

        for (int b = 0; b < blocks; b++)
        {
            double[] x = new double[blockSize];
            for (int n = 0; n < blockSize; n++)
            {
                int idx = b * blockSize + n;
                x[n] = idx < plainBytes.Length ? plainBytes[idx] : 0.0;
            }

            for (int k = 0; k < blockSize; k++)
            {
                double re = 0, im = 0;
                for (int n = 0; n < blockSize; n++)
                {
                    double angle = -2.0 * Math.PI * k * n / blockSize;
                    re += x[n] * Math.Cos(angle);
                    im += x[n] * Math.Sin(angle);
                }

                // Rotación espectral de fase dependiente de la llave secreta
                double phaseKey = (phaseSeed[k] / 255.0) * 2.0 * Math.PI;
                double rotRe = re * Math.Cos(phaseKey) - im * Math.Sin(phaseKey);
                double rotIm = re * Math.Sin(phaseKey) + im * Math.Cos(phaseKey);

                bw.Write(rotRe);
                bw.Write(rotIm);
            }
        }

        byte[] spectralBytes = ms.ToArray();
        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = spectralBytes,
            SecretKeyBase64 = Convert.ToBase64String(phaseSeed),
            PublicParametersJson = JsonSerializer.Serialize(new
            {
                transform = "DFT-16 Phase-Modulated",
                blockSize,
                blocks,
                originalLength = plainBytes.Length
            }),
            Summary = $"DFTSPECTRAL transformado al dominio de frecuencias ({blocks} bloques, {spectralBytes.Length} bytes)."
        };
    }

    public CryptoOperationResult Decrypt(byte[] cipherBytes, string secretKeyBase64, string publicParametersJson)
    {
        const int blockSize = 16;
        byte[] phaseSeed = KeyInputParser.ResolveFixedLengthKey(secretKeyBase64, blockSize, "DFTSPECTRAL");

        if (cipherBytes.Length < 4)
            throw new CryptographicException("Datos cifrados DFTSPECTRAL incompletos.");

        using var ms = new MemoryStream(cipherBytes);
        using var br = new BinaryReader(ms);
        int origLen = br.ReadInt32();
        if (origLen < 0 || origLen > 50_000_000)
            throw new CryptographicException("Cabecera DFTSPECTRAL inválida.");
        int blocks = Math.Max(1, (origLen + blockSize - 1) / blockSize);

        byte[] output = new byte[origLen];
        for (int b = 0; b < blocks; b++)
        {
            double[] re = new double[blockSize];
            double[] im = new double[blockSize];
            for (int k = 0; k < blockSize; k++)
            {
                double rotRe = br.ReadDouble();
                double rotIm = br.ReadDouble();
                double phaseKey = -(phaseSeed[k] / 255.0) * 2.0 * Math.PI;
                re[k] = rotRe * Math.Cos(phaseKey) - rotIm * Math.Sin(phaseKey);
                im[k] = rotRe * Math.Sin(phaseKey) + rotIm * Math.Cos(phaseKey);
            }

            // IDFT
            for (int n = 0; n < blockSize; n++)
            {
                int idx = b * blockSize + n;
                if (idx >= origLen) break;

                double sum = 0;
                for (int k = 0; k < blockSize; k++)
                {
                    double angle = 2.0 * Math.PI * k * n / blockSize;
                    sum += re[k] * Math.Cos(angle) - im[k] * Math.Sin(angle);
                }
                output[idx] = (byte)Math.Clamp((int)Math.Round(sum / blockSize), 0, 255);
            }
        }

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = output,
            SecretKeyBase64 = secretKeyBase64,
            PublicParametersJson = publicParametersJson,
            Summary = $"IDFT espectral reconstruida con precisión ({output.Length} bytes)."
        };
    }
}

/// <summary>20. LAGRANGESHAMIR — Umbral Shamir GF(256)</summary>
public sealed class LagrangeShamirStrategy : ICryptoStrategy
{
    public CryptoAlgorithmInfo Info { get; } = new()
    {
        Code = "LAGRANGESHAMIR",
        DisplayName = "Umbral Shamir GF(256)",
        Category = "Secret Sharing / Umbral",
        Description = "Esquema umbral (t=3, n=5) de Shamir sobre campo finito GF(2^8) con interpolación de Lagrange."
    };

    public CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase = null)
    {
        const int threshold = 3;
        const int totalShares = 5;

        // Dividimos una llave maestra de 32 bytes mediante Shamir (3,5) en GF(256) y protegemos el payload con AES-GCM
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        byte[][] shares = SplitSecretGf256(masterKey, threshold, totalShares);

        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] cipher = new byte[plainBytes.Length];
        byte[] tag = new byte[16];
        using (var aes = new AesGcm(masterKey, 16))
            aes.Encrypt(nonce, plainBytes, cipher, tag);

        // Guardamos 3 fragmentos en el secreto (umbral mínimo para reconstruir vía Lagrange)
        var thresholdShares = new[]
        {
            new { x = 1, y = Convert.ToBase64String(shares[0]) },
            new { x = 3, y = Convert.ToBase64String(shares[2]) },
            new { x = 5, y = Convert.ToBase64String(shares[4]) }
        };

        string secretJson = JsonSerializer.Serialize(thresholdShares);
        string pubJson = JsonSerializer.Serialize(new
        {
            field = "GF(2^8) poly=0x11B",
            thresholdT = threshold,
            totalSharesN = totalShares,
            nonce = Convert.ToBase64String(nonce),
            tag = Convert.ToBase64String(tag)
        });

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = cipher,
            SecretKeyBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(secretJson)),
            PublicParametersJson = pubJson,
            Summary = $"Shamir GF(256) umbral (3/5) generado y cifrado ({cipher.Length} bytes)."
        };
    }

    public CryptoOperationResult Decrypt(byte[] cipherBytes, string secretKeyBase64, string publicParametersJson)
    {
        string trimmedSec = (secretKeyBase64 ?? string.Empty).Trim();
        string secretJson;
        if (trimmedSec.StartsWith('['))
        {
            secretJson = trimmedSec;
        }
        else if (KeyInputParser.TryDecodeFlexibleBase64(trimmedSec, out byte[] rawShares))
        {
            secretJson = Encoding.UTF8.GetString(rawShares);
        }
        else
        {
            throw new CryptographicException("Secretos Lagrange/Shamir inválidos (se esperaba JSON o Base64 de shares). Si proviene de otro nodo, delega el descifrado al nodo dueño.");
        }

        using var sharesDoc = JsonDocument.Parse(secretJson);
        var xs = new List<byte>();
        var ys = new List<byte[]>();

        foreach (var item in sharesDoc.RootElement.EnumerateArray())
        {
            xs.Add((byte)item.GetProperty("x").GetInt32());
            string yStr = KeyInputParser.TryGetJsonString(item, out string ysVal, "y") ? ysVal : string.Empty;
            if (!KeyInputParser.TryDecodeFlexibleBase64(yStr, out byte[] yBytes))
                throw new CryptographicException("Share Shamir 'y' con Base64 inválido.");
            ys.Add(yBytes);
        }

        byte[] masterKey = CombineSecretGf256(xs.ToArray(), ys.ToArray());

        using var pubDoc = JsonDocument.Parse(publicParametersJson);
        if (!KeyInputParser.TryGetJsonString(pubDoc.RootElement, out string nonceStr, "nonce", "iv", "ivBase64") ||
            !KeyInputParser.TryDecodeBase64OrHex(nonceStr, out byte[] nonce))
            throw new CryptographicException("Parámetro público 'nonce' inválido en LAGRANGESHAMIR.");
        if (!KeyInputParser.TryGetJsonString(pubDoc.RootElement, out string tagStr, "tag", "authTag", "tagBase64") ||
            !KeyInputParser.TryDecodeBase64OrHex(tagStr, out byte[] tag))
            throw new CryptographicException("Parámetro público 'tag' inválido en LAGRANGESHAMIR.");

        byte[] plain = new byte[cipherBytes.Length];

        using (var aes = new AesGcm(masterKey, 16))
            aes.Decrypt(nonce, cipherBytes, tag, plain);

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = plain,
            SecretKeyBase64 = secretKeyBase64 ?? string.Empty,
            PublicParametersJson = publicParametersJson,
            Summary = $"Interpolación Lagrange GF(256) reconstruyó llave y descifró ({plain.Length} bytes)."
        };
    }

    private static byte[][] SplitSecretGf256(byte[] secret, int t, int n)
    {
        byte[][] shares = new byte[n][];
        for (int i = 0; i < n; i++) shares[i] = new byte[secret.Length];

        byte[] coeffs = new byte[t];
        for (int b = 0; b < secret.Length; b++)
        {
            coeffs[0] = secret[b];
            for (int c = 1; c < t; c++)
                coeffs[c] = (byte)RandomNumberGenerator.GetInt32(1, 256);

            for (int i = 0; i < n; i++)
            {
                byte x = (byte)(i + 1);
                byte y = 0;
                for (int c = t - 1; c >= 0; c--)
                    y = (byte)(GfMul(y, x) ^ coeffs[c]);
                shares[i][b] = y;
            }
        }
        return shares;
    }

    private static byte[] CombineSecretGf256(byte[] xs, byte[][] ys)
    {
        int len = ys[0].Length;
        byte[] secret = new byte[len];
        int k = xs.Length;

        for (int b = 0; b < len; b++)
        {
            byte acc = 0;
            for (int i = 0; i < k; i++)
            {
                byte basis = 1;
                for (int j = 0; j < k; j++)
                {
                    if (i == j) continue;
                    byte num = xs[j];
                    byte den = (byte)(xs[i] ^ xs[j]);
                    basis = GfMul(basis, GfDiv(num, den));
                }
                acc ^= GfMul(ys[i][b], basis);
            }
            secret[b] = acc;
        }
        return secret;
    }

    private static byte GfMul(byte a, byte b)
    {
        byte p = 0;
        for (int i = 0; i < 8; i++)
        {
            if ((b & 1) != 0) p ^= a;
            bool hi = (a & 0x80) != 0;
            a <<= 1;
            if (hi) a ^= 0x1B;
            b >>= 1;
        }
        return p;
    }

    private static byte GfPow(byte a, int exp)
    {
        byte res = 1;
        while (exp > 0)
        {
            if ((exp & 1) != 0) res = GfMul(res, a);
            a = GfMul(a, a);
            exp >>= 1;
        }
        return res;
    }

    private static byte GfDiv(byte a, byte b) => GfMul(a, GfPow(b, 254));
}
