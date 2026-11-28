using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ModuloCrypto.Security.Strategies;

/// <summary>8. CAESAR — Cifrado César</summary>
public sealed class CaesarStrategy : ICryptoStrategy
{
    public CryptoAlgorithmInfo Info { get; } = new()
    {
        Code = "CAESAR",
        DisplayName = "Cifrado César",
        Category = "Clásico Sustitución",
        Description = "Desplazamiento modular César sobre espacio completo de bytes (mod 256)."
    };

    public CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase = null)
    {
        int shift = string.IsNullOrWhiteSpace(optionalPassphrase)
            ? RandomNumberGenerator.GetInt32(1, 255)
            : (Math.Abs(optionalPassphrase.Sum(c => c)) % 254) + 1;

        byte[] cipher = new byte[plainBytes.Length];
        for (int i = 0; i < plainBytes.Length; i++)
            cipher[i] = (byte)((plainBytes[i] + shift) & 0xFF);

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = cipher,
            SecretKeyBase64 = Convert.ToBase64String(new[] { (byte)shift }),
            PublicParametersJson = JsonSerializer.Serialize(new { alphabet = "BYTE-256", shiftHint = "Protected" }),
            Summary = $"Cifrado César aplicado (shift={shift}, {cipher.Length} bytes)."
        };
    }

    public CryptoOperationResult Decrypt(byte[] cipherBytes, string secretKeyBase64, string publicParametersJson)
    {
        string alphabet = "BYTE";
        if (!string.IsNullOrWhiteSpace(publicParametersJson))
        {
            try
            {
                using var doc = JsonDocument.Parse(publicParametersJson);
                if (KeyInputParser.TryGetJsonString(doc.RootElement, out string parsedAlphabet, "alphabet", "space", "mode"))
                    alphabet = parsedAlphabet.Trim();
            }
            catch { }
        }

        if (!KeyInputParser.TryParseIntegerKey(secretKeyBase64, out int rawShift))
            throw new CryptographicException("Llave César inválida: se esperaba un desplazamiento entero o Base64 de 1/4 bytes.");

        byte[] plain = new byte[cipherBytes.Length];
        if (string.Equals(alphabet, "A-Z", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(alphabet, "AZ", StringComparison.OrdinalIgnoreCase))
        {
            int s = ((rawShift % 26) + 26) % 26;
            for (int i = 0; i < cipherBytes.Length; i++)
            {
                byte b = cipherBytes[i];
                if (b is >= (byte)'A' and <= (byte)'Z')
                    plain[i] = (byte)('A' + ((b - 'A' - s + 26) % 26));
                else if (b is >= (byte)'a' and <= (byte)'z')
                    plain[i] = (byte)('a' + ((b - 'a' - s + 26) % 26));
                else
                    plain[i] = b;
            }
        }
        else
        {
            int shift = ((rawShift % 256) + 256) % 256;
            for (int i = 0; i < cipherBytes.Length; i++)
                plain[i] = (byte)((cipherBytes[i] - shift + 256) & 0xFF);
        }

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = plain,
            SecretKeyBase64 = secretKeyBase64,
            PublicParametersJson = publicParametersJson,
            Summary = $"Cifrado César descifrado ({plain.Length} bytes, {alphabet})."
        };
    }
}

/// <summary>9. VIGENERE — Cifrado Vigenère</summary>
public sealed class VigenereStrategy : ICryptoStrategy
{
    public CryptoAlgorithmInfo Info { get; } = new()
    {
        Code = "VIGENERE",
        DisplayName = "Cifrado Vigenère",
        Category = "Clásico Polialfabético",
        Description = "Sustitución polialfabética Vigenère extendida a bytes (mod 256)."
    };

    public CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase = null)
    {
        byte[] key = string.IsNullOrWhiteSpace(optionalPassphrase)
            ? RandomNumberGenerator.GetBytes(16)
            : Encoding.UTF8.GetBytes(optionalPassphrase);

        byte[] cipher = new byte[plainBytes.Length];
        for (int i = 0; i < plainBytes.Length; i++)
            cipher[i] = (byte)((plainBytes[i] + key[i % key.Length]) & 0xFF);

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = cipher,
            SecretKeyBase64 = Convert.ToBase64String(key),
            PublicParametersJson = JsonSerializer.Serialize(new { keyLength = key.Length, space = "BYTE-256" }),
            Summary = $"Vigenère cifrado (llave {key.Length} bytes, {cipher.Length} bytes)."
        };
    }

    public CryptoOperationResult Decrypt(byte[] cipherBytes, string secretKeyBase64, string publicParametersJson)
    {
        string alphabet = "BYTE";
        int? keyLength = null;
        if (!string.IsNullOrWhiteSpace(publicParametersJson))
        {
            try
            {
                using var doc = JsonDocument.Parse(publicParametersJson);
                if (KeyInputParser.TryGetJsonString(doc.RootElement, out string parsedAlphabet, "alphabet", "space", "mode"))
                    alphabet = parsedAlphabet.Trim();
                if (KeyInputParser.TryGetJsonInt(doc.RootElement, out int kl, "keyLength"))
                {
                    if (kl > 0) keyLength = kl;
                }
            }
            catch { }
        }

        byte[] plain = new byte[cipherBytes.Length];
        if (string.Equals(alphabet, "A-Z", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(alphabet, "AZ", StringComparison.OrdinalIgnoreCase))
        {
            string trimmed = (secretKeyBase64 ?? string.Empty).Trim();
            byte[] keySource = KeyInputParser.HasExplicitBase64Markers(trimmed) &&
                               KeyInputParser.TryDecodeBase64Strict(trimmed, out var decodedAz)
                ? decodedAz
                : Encoding.UTF8.GetBytes(trimmed);

            var shifts = new List<int>(keySource.Length);
            foreach (byte kb in keySource)
            {
                if (kb is >= (byte)'A' and <= (byte)'Z') shifts.Add(kb - 'A');
                else if (kb is >= (byte)'a' and <= (byte)'z') shifts.Add(kb - 'a');
            }

            if (shifts.Count == 0)
                throw new CryptographicException("Llave Vigenère inválida para alfabeto A-Z.");

            int kIdx = 0;
            for (int i = 0; i < cipherBytes.Length; i++)
            {
                byte b = cipherBytes[i];
                if (b is >= (byte)'A' and <= (byte)'Z')
                {
                    int s = shifts[kIdx % shifts.Count];
                    kIdx++;
                    plain[i] = (byte)('A' + ((b - 'A' - s + 26) % 26));
                }
                else if (b is >= (byte)'a' and <= (byte)'z')
                {
                    int s = shifts[kIdx % shifts.Count];
                    kIdx++;
                    plain[i] = (byte)('a' + ((b - 'a' - s + 26) % 26));
                }
                else
                {
                    plain[i] = b;
                }
            }
        }
        else
        {
            byte[] key = KeyInputParser.ParseRawOrTextKey(
                secretKeyBase64,
                expectedBytes: keyLength,
                preferBase64WithoutPadding: keyLength.HasValue && keyLength.Value >= 16);

            if (key.Length == 0)
                throw new CryptographicException("Llave Vigenère vacía o inválida.");

            for (int i = 0; i < cipherBytes.Length; i++)
                plain[i] = (byte)((cipherBytes[i] - key[i % key.Length] + 256) & 0xFF);
        }

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = plain,
            SecretKeyBase64 = secretKeyBase64 ?? string.Empty,
            PublicParametersJson = publicParametersJson,
            Summary = $"Vigenère descifrado ({plain.Length} bytes, {alphabet})."
        };
    }
}

/// <summary>10. XORASM — XOR en Registro (simulación de operaciones de registro ROL/XOR de 64 bits)</summary>
public sealed class XorAsmStrategy : ICryptoStrategy
{
    public CryptoAlgorithmInfo Info { get; } = new()
    {
        Code = "XORASM",
        DisplayName = "XOR en Registro",
        Category = "Bajo Nivel / Registro",
        Description = "Flujo XOR con rotación de registros de 64 bits (ROL/XOR estilo ensamblador x64)."
    };

    public CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase = null)
    {
        byte[] key = string.IsNullOrWhiteSpace(optionalPassphrase)
            ? RandomNumberGenerator.GetBytes(16)
            : SHA256.HashData(Encoding.UTF8.GetBytes(optionalPassphrase))[..16];
        byte[] iv = RandomNumberGenerator.GetBytes(8);
        byte[] output = Transform(plainBytes, key, iv);

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = output,
            SecretKeyBase64 = Convert.ToBase64String(key),
            PublicParametersJson = JsonSerializer.Serialize(new { registerWidth = "64-bit ROL/XOR", iv = Convert.ToBase64String(iv) }),
            Summary = $"XORASM (registro RAX/RBX 64-bit) aplicado ({output.Length} bytes)."
        };
    }

    public CryptoOperationResult Decrypt(byte[] cipherBytes, string secretKeyBase64, string publicParametersJson)
    {
        JsonDocument? doc = null;
        try
        {
            if (!string.IsNullOrWhiteSpace(publicParametersJson))
                doc = JsonDocument.Parse(publicParametersJson);

            byte[] plain;
            if (doc != null &&
                KeyInputParser.TryGetJsonString(doc.RootElement, out string ivStr, "iv", "ivBase64", "nonce") &&
                !string.IsNullOrWhiteSpace(ivStr))
            {
                if (!KeyInputParser.TryDecodeBase64OrHex(ivStr, out byte[] iv) || iv.Length < 8)
                    throw new CryptographicException("IV de XORASM inválido o corrupto.");

                byte[] nativeKey = KeyInputParser.ResolveFixedLengthKey(secretKeyBase64, 16, "XORASM");
                plain = Transform(cipherBytes, nativeKey, iv);
            }
            else
            {
                string rotation = "NONE";
                int rotationBits = 0;
                int? expectedKeyLen = null;

                if (doc != null)
                {
                    if (KeyInputParser.TryGetJsonString(doc.RootElement, out string rot, "rotation", "rotateDirection", "op"))
                        rotation = rot.Trim().ToUpperInvariant();
                    if (KeyInputParser.TryGetJsonInt(doc.RootElement, out int rBits, "rotationBits", "rotBits", "bits"))
                        rotationBits = rBits;
                    if (KeyInputParser.TryGetJsonInt(doc.RootElement, out int kl, "keyLength"))
                        expectedKeyLen = kl > 0 ? kl : null;
                }

                byte[] key = KeyInputParser.ParseRawOrTextKey(secretKeyBase64, expectedBytes: expectedKeyLen);
                if (key.Length == 0)
                    throw new CryptographicException("Llave XORASM vacía o inválida.");

                int r = ((rotationBits % 8) + 8) % 8;
                plain = new byte[cipherBytes.Length];
                for (int i = 0; i < cipherBytes.Length; i++)
                {
                    byte b = cipherBytes[i];
                    byte unrotated = rotation switch
                    {
                        "ROL" when r > 0 => (byte)(((b >> r) | (b << (8 - r))) & 0xFF),
                        "ROR" when r > 0 => (byte)(((b << r) | (b >> (8 - r))) & 0xFF),
                        _ => b
                    };
                    plain[i] = (byte)(unrotated ^ key[i % key.Length]);
                }
            }

            return new CryptoOperationResult
            {
                AlgorithmCode = Info.Code,
                OutputBytes = plain,
                SecretKeyBase64 = secretKeyBase64,
                PublicParametersJson = publicParametersJson,
                Summary = $"XORASM revertido con éxito ({plain.Length} bytes)."
            };
        }
        finally
        {
            doc?.Dispose();
        }
    }

    private static byte[] Transform(byte[] data, byte[] key, byte[] iv)
    {
        ulong rax = BinaryPrimitives.ReadUInt64LittleEndian(key.AsSpan(0, 8));
        ulong rbx = BinaryPrimitives.ReadUInt64LittleEndian(key.AsSpan(8, 8));
        ulong rcx = BinaryPrimitives.ReadUInt64LittleEndian(iv);
        byte[] result = new byte[data.Length];

        for (int i = 0; i < data.Length; i++)
        {
            rax = ((rax << 7) | (rax >> 57)) ^ rbx;
            rcx = ((rcx << 13) | (rcx >> 51)) + 0x9E3779B97F4A7C15UL;
            byte mask = (byte)((rax ^ rcx) & 0xFF);
            result[i] = (byte)(data[i] ^ mask);
        }
        return result;
    }
}

/// <summary>12. EUCLIDESAFFINE — Euclides Extendido / Afín</summary>
public sealed class EuclidesAffineStrategy : ICryptoStrategy
{
    public CryptoAlgorithmInfo Info { get; } = new()
    {
        Code = "EUCLIDESAFFINE",
        DisplayName = "Euclides Extendido / Afín",
        Category = "Teoría de Números",
        Description = "Cifrado Afín E(x)=(ax+b) mod 256 con inverso multiplicativo calculado vía Euclides Extendido."
    };

    public CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase = null)
    {
        // 'a' debe ser coprimo con 256 (cualquier impar en [3..253])
        int a = (RandomNumberGenerator.GetInt32(1, 126) * 2) + 1;
        int b = RandomNumberGenerator.GetInt32(1, 255);
        int aInv = ModInverse(a, 256);

        byte[] cipher = new byte[plainBytes.Length];
        for (int i = 0; i < plainBytes.Length; i++)
            cipher[i] = (byte)((a * plainBytes[i] + b) & 0xFF);

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = cipher,
            SecretKeyBase64 = Convert.ToBase64String(new[] { (byte)a, (byte)b, (byte)aInv }),
            PublicParametersJson = JsonSerializer.Serialize(new { modulus = 256, gcdCheck = "gcd(a,256)=1", formula = "E(x)=(a*x+b) mod 256" }),
            Summary = $"Afín (a={a}, b={b}, a^-1={aInv} mod 256) cifrado ({cipher.Length} bytes)."
        };
    }

    public CryptoOperationResult Decrypt(byte[] cipherBytes, string secretKeyBase64, string publicParametersJson)
    {
        int modulus = 256;
        if (!string.IsNullOrWhiteSpace(publicParametersJson))
        {
            try
            {
                using var doc = JsonDocument.Parse(publicParametersJson);
                if (KeyInputParser.TryGetJsonInt(doc.RootElement, out int parsedMod, "modulus", "m") && parsedMod > 1)
                    modulus = parsedMod;
            }
            catch { }
        }

        if (!TryParseAffineKey(secretKeyBase64, out int a, out int b))
            throw new CryptographicException("Llave Afín inválida: usa formato \"a,b\", JSON {\"a\":...,\"b\":...} o Base64 de 3 bytes.");

        a = ((a % modulus) + modulus) % modulus;
        b = ((b % modulus) + modulus) % modulus;
        int aInv = ModInverse(a, modulus);

        byte[] plain = new byte[cipherBytes.Length];
        if (modulus == 26)
        {
            for (int i = 0; i < cipherBytes.Length; i++)
            {
                byte ch = cipherBytes[i];
                if (ch is >= (byte)'A' and <= (byte)'Z')
                    plain[i] = (byte)('A' + ((aInv * (((ch - 'A') - b + 26) % 26)) % 26));
                else if (ch is >= (byte)'a' and <= (byte)'z')
                    plain[i] = (byte)('a' + ((aInv * (((ch - 'a') - b + 26) % 26)) % 26));
                else
                    plain[i] = ch;
            }
        }
        else
        {
            for (int i = 0; i < cipherBytes.Length; i++)
                plain[i] = (byte)((aInv * (((cipherBytes[i] - b) % modulus + modulus) % modulus)) % modulus);
        }

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = plain,
            SecretKeyBase64 = secretKeyBase64,
            PublicParametersJson = publicParametersJson,
            Summary = $"Afín descifrado con inverso modular a^-1={aInv} mod {modulus} ({plain.Length} bytes)."
        };
    }

    private static bool TryParseAffineKey(string? input, out int a, out int b)
    {
        a = 0;
        b = 0;
        if (string.IsNullOrWhiteSpace(input)) return false;

        string trimmed = input.Trim();
        if (trimmed.StartsWith('{'))
        {
            try
            {
                using var doc = JsonDocument.Parse(trimmed);
                if (KeyInputParser.TryGetJsonInt(doc.RootElement, out a, "a") &&
                    KeyInputParser.TryGetJsonInt(doc.RootElement, out b, "b"))
                {
                    return true;
                }
            }
            catch { }
        }

        var parts = trimmed.Split(new[] { ',', ';', ':', ' ', '\t', '|', '/' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length >= 2)
        {
            string p0 = parts[0].StartsWith("a=", StringComparison.OrdinalIgnoreCase) ? parts[0][2..] : parts[0];
            string p1 = parts[1].StartsWith("b=", StringComparison.OrdinalIgnoreCase) ? parts[1][2..] : parts[1];
            if (int.TryParse(p0, NumberStyles.Integer, CultureInfo.InvariantCulture, out a) &&
                int.TryParse(p1, NumberStyles.Integer, CultureInfo.InvariantCulture, out b))
            {
                return true;
            }
        }

        if (KeyInputParser.TryDecodeBase64OrHex(trimmed, out byte[] raw) && raw.Length >= 2)
        {
            a = raw[0];
            b = raw[1];
            return true;
        }

        return false;
    }

    private static int ModInverse(int a, int m)
    {
        int t = 0, newT = 1;
        int r = m, newR = ((a % m) + m) % m;
        while (newR != 0)
        {
            int q = r / newR;
            (t, newT) = (newT, t - q * newT);
            (r, newR) = (newR, r - q * newR);
        }
        if (r != 1) throw new CryptographicException($"No existe inverso modular para a={a} mod {m} (gcd={r}).");
        if (t < 0) t += m;
        return t;
    }
}

/// <summary>14. FISHERYATES — Permutación Fisher-Yates</summary>
public sealed class FisherYatesStrategy : ICryptoStrategy
{
    public CryptoAlgorithmInfo Info { get; } = new()
    {
        Code = "FISHERYATES",
        DisplayName = "Permutación Fisher-Yates",
        Category = "Transposición",
        Description = "Transposición criptográfica Fisher-Yates determinista con semilla de 256 bits."
    };

    public CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase = null)
    {
        byte[] seed = string.IsNullOrWhiteSpace(optionalPassphrase)
            ? RandomNumberGenerator.GetBytes(32)
            : SHA256.HashData(Encoding.UTF8.GetBytes(optionalPassphrase));

        int[] perm = BuildPermutation(plainBytes.Length, seed);
        byte[] cipher = new byte[plainBytes.Length];
        for (int i = 0; i < plainBytes.Length; i++)
            cipher[i] = plainBytes[perm[i]];

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = cipher,
            SecretKeyBase64 = Convert.ToBase64String(seed),
            PublicParametersJson = JsonSerializer.Serialize(new { length = plainBytes.Length, prng = "SHA256-CTR-FisherYates" }),
            Summary = $"Permutación Fisher-Yates aplicada ({cipher.Length} elementos)."
        };
    }

    public CryptoOperationResult Decrypt(byte[] cipherBytes, string secretKeyBase64, string publicParametersJson)
    {
        byte[] seed = KeyInputParser.ParseRawOrTextKey(secretKeyBase64, expectedBytes: 32, preferBase64WithoutPadding: true);
        if (seed.Length == 0)
            throw new CryptographicException("Semilla Fisher-Yates vacía o inválida.");

        int[] perm = BuildPermutation(cipherBytes.Length, seed);
        byte[] plain = new byte[cipherBytes.Length];
        for (int i = 0; i < cipherBytes.Length; i++)
            plain[perm[i]] = cipherBytes[i];

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = plain,
            SecretKeyBase64 = secretKeyBase64,
            PublicParametersJson = publicParametersJson,
            Summary = $"Permutación inversa Fisher-Yates completada ({plain.Length} bytes)."
        };
    }

    private static int[] BuildPermutation(int n, byte[] seed)
    {
        int[] indices = new int[n];
        for (int i = 0; i < n; i++) indices[i] = i;

        uint counter = 0;
        byte[] buffer = Array.Empty<byte>();
        int bufPos = 0;

        uint NextUInt32()
        {
            if (bufPos + 4 > buffer.Length)
            {
                byte[] input = new byte[seed.Length + 4];
                Buffer.BlockCopy(seed, 0, input, 0, seed.Length);
                BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(seed.Length), counter++);
                buffer = SHA256.HashData(input);
                bufPos = 0;
            }
            uint val = BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(bufPos, 4));
            bufPos += 4;
            return val;
        }

        for (int i = n - 1; i > 0; i--)
        {
            int j = (int)(NextUInt32() % (uint)(i + 1));
            (indices[i], indices[j]) = (indices[j], indices[i]);
        }
        return indices;
    }
}

/// <summary>21. LORENZSZ40 — Cifrado Lorenz SZ40/42</summary>
public sealed class LorenzSz40Strategy : ICryptoStrategy
{
    // Longitudes históricas reales de los 12 rotores de la máquina Lorenz SZ40/42
    private static readonly int[] ChiLengths = { 41, 31, 29, 26, 23 };
    private static readonly int[] PsiLengths = { 43, 47, 51, 53, 59 };
    private const int Mu61Length = 61;
    private const int Mu37Length = 37;

    public CryptoAlgorithmInfo Info { get; } = new()
    {
        Code = "LORENZSZ40",
        DisplayName = "Cifrado Lorenz SZ40/42",
        Category = "Histórico Electromecánico",
        Description = "Simulación de máquina de flujo de 12 rotores Lorenz SZ40/42 (ruedas Chi, Psi y motores Mu61/Mu37)."
    };

    public CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase = null)
    {
        byte[] keySeed = string.IsNullOrWhiteSpace(optionalPassphrase)
            ? RandomNumberGenerator.GetBytes(24)
            : SHA256.HashData(Encoding.UTF8.GetBytes(optionalPassphrase))[..24];

        byte[] output = ApplyLorenzStream(plainBytes, keySeed);

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = output,
            SecretKeyBase64 = Convert.ToBase64String(keySeed),
            PublicParametersJson = JsonSerializer.Serialize(new
            {
                wheels = 12,
                chi = ChiLengths,
                psi = PsiLengths,
                motors = new[] { Mu61Length, Mu37Length }
            }),
            Summary = $"Lorenz SZ40/42 flujo Vernam 12-rotores aplicado ({output.Length} bytes)."
        };
    }

    public CryptoOperationResult Decrypt(byte[] cipherBytes, string secretKeyBase64, string publicParametersJson)
    {
        byte[] keySeed = KeyInputParser.ParseRawOrTextKey(secretKeyBase64, expectedBytes: 24, preferBase64WithoutPadding: true);
        if (keySeed.Length == 0)
            throw new CryptographicException("Semilla Lorenz SZ40/42 vacía o inválida.");

        byte[] plain = ApplyLorenzStream(cipherBytes, keySeed);

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = plain,
            SecretKeyBase64 = secretKeyBase64,
            PublicParametersJson = publicParametersJson,
            Summary = $"Lorenz SZ40/42 flujo revertido ({plain.Length} bytes)."
        };
    }

    private static byte[] ApplyLorenzStream(byte[] data, byte[] seed)
    {
        // Generar pines binarios de los 12 rotores a partir de la semilla
        byte[] expanded = SHA512.HashData(seed);
        bool[][] chi = BuildWheels(ChiLengths, expanded, 0);
        bool[][] psi = BuildWheels(PsiLengths, expanded, 17);
        bool[] mu61 = BuildWheel(Mu61Length, expanded, 37);
        bool[] mu37 = BuildWheel(Mu37Length, expanded, 49);

        int[] chiPos = new int[5];
        int[] psiPos = new int[5];
        for (int i = 0; i < 5; i++)
        {
            chiPos[i] = seed[i] % ChiLengths[i];
            psiPos[i] = seed[5 + i] % PsiLengths[i];
        }
        int mu61Pos = seed[10] % Mu61Length;
        int mu37Pos = seed[11] % Mu37Length;

        byte[] result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
        {
            int keyByte = 0;
            // Generamos 8 bits combinando dos pasos Baudot (5-bit + 3-bit)
            for (int bit = 0; bit < 8; bit++)
            {
                int w = bit % 5;
                bool cBit = chi[w][chiPos[w]];
                bool pBit = psi[w][psiPos[w]];
                if (cBit ^ pBit)
                    keyByte |= (1 << bit);

                if (w == 4 || bit == 7)
                {
                    for (int k = 0; k < 5; k++)
                        chiPos[k] = (chiPos[k] + 1) % ChiLengths[k];

                    bool stepMu37 = mu61[mu61Pos];
                    mu61Pos = (mu61Pos + 1) % Mu61Length;

                    bool stepPsi = mu37[mu37Pos];
                    if (stepMu37)
                        mu37Pos = (mu37Pos + 1) % Mu37Length;

                    if (stepPsi)
                    {
                        for (int k = 0; k < 5; k++)
                            psiPos[k] = (psiPos[k] + 1) % PsiLengths[k];
                    }
                }
            }
            result[i] = (byte)(data[i] ^ keyByte);
        }
        return result;
    }

    private static bool[][] BuildWheels(int[] lengths, byte[] hash, int offset)
    {
        bool[][] wheels = new bool[lengths.Length][];
        for (int i = 0; i < lengths.Length; i++)
            wheels[i] = BuildWheel(lengths[i], hash, offset + i * 3);
        return wheels;
    }

    private static bool[] BuildWheel(int len, byte[] hash, int salt)
    {
        bool[] pins = new bool[len];
        for (int i = 0; i < len; i++)
        {
            byte b = hash[(i + salt) % hash.Length];
            pins[i] = ((b >> (i % 8)) & 1) == 1;
        }
        return pins;
    }
}
