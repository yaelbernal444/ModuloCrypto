using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ModuloCrypto.Security.Strategies;

/// <summary>
/// Utilidad tolerante y sin excepciones no controladas para parsear llaves/secretos en múltiples formatos
/// (Base64 estándar/URL-safe/sin padding, Hex, UTF-8 plano, enteros o JSON de parámetros) al interoperar con nodos v2.0.
/// </summary>
internal static class KeyInputParser
{
    public static bool HasExplicitBase64Markers(string? trimmedInput)
    {
        if (string.IsNullOrEmpty(trimmedInput)) return false;
        return trimmedInput.Contains('=') || trimmedInput.Contains('+') || trimmedInput.Contains('/');
    }

    public static bool TryDecodeBase64Strict(string? input, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(input)) return false;

        string trimmed = input.Trim();
        if (trimmed.Length == 0 || trimmed.Length % 4 != 0)
            return false;

        byte[] buffer = new byte[(trimmed.Length * 3) / 4 + 4];
        if (!Convert.TryFromBase64String(trimmed, buffer, out int written))
            return false;

        bytes = buffer[..written];
        return true;
    }

    public static bool TryDecodeFlexibleBase64(string? input, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(input)) return false;

        string trimmed = input.Trim();
        if (TryDecodeBase64Strict(trimmed, out bytes))
            return true;

        // Soporte URL-safe (- / _) o Base64 sin padding '='
        string normalized = trimmed.Replace('-', '+').Replace('_', '/');
        int mod = normalized.Length % 4;
        if (mod == 1) return false;
        if (mod == 2) normalized += "==";
        else if (mod == 3) normalized += "=";

        return TryDecodeBase64Strict(normalized, out bytes);
    }

    public static bool TryDecodeHex(string? input, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(input)) return false;

        string cleaned = input.Trim();
        if (cleaned.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            cleaned = cleaned[2..];

        if (cleaned.Length == 0 || cleaned.Length % 2 != 0)
            return false;

        foreach (char c in cleaned)
        {
            if (!Uri.IsHexDigit(c))
                return false;
        }

        try
        {
            bytes = Convert.FromHexString(cleaned);
            return true;
        }
        catch
        {
            bytes = Array.Empty<byte>();
            return false;
        }
    }

    /// <summary>
    /// Resuelve un secreto sin confundir cadenas ASCII como "CRIPTOGRAFIA" o "clave123" con Base64 binario.
    /// </summary>
    public static byte[] ParseRawOrTextKey(string? input, int? expectedBytes = null, bool preferBase64WithoutPadding = false)
    {
        if (string.IsNullOrEmpty(input))
            return Array.Empty<byte>();

        string trimmed = input.Trim();
        if (trimmed.Length == 0)
            return Array.Empty<byte>();

        // 1. Hex explícito con prefijo 0x
        if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && TryDecodeHex(trimmed, out var explicitHex))
        {
            if (expectedBytes == null || explicitHex.Length == expectedBytes.Value)
                return explicitHex;
        }

        // 2. Longitud esperada explícita (por ej. keyLength en Vigenere o 16/24/32 bytes)
        if (expectedBytes is > 0)
        {
            if (trimmed.Length == expectedBytes.Value * 2 && TryDecodeHex(trimmed, out var exactHex) && exactHex.Length == expectedBytes.Value)
                return exactHex;

            if (TryDecodeBase64Strict(trimmed, out var exactB64) && exactB64.Length == expectedBytes.Value)
                return exactB64;

            byte[] utf8Exact = Encoding.UTF8.GetBytes(trimmed);
            if (utf8Exact.Length == expectedBytes.Value)
                return utf8Exact;
        }

        // 3. Base64 explícito (contiene '=', '+' o '/')
        if (HasExplicitBase64Markers(trimmed) && TryDecodeBase64Strict(trimmed, out var markedB64))
            return markedB64;

        // 4. Base64 largo sin padding (ej. llaves >= 24 bytes = >= 32 chars) o cuando se indica explícitamente
        if ((preferBase64WithoutPadding || trimmed.Length >= 24) &&
            trimmed.Length % 4 == 0 &&
            TryDecodeBase64Strict(trimmed, out var longB64))
        {
            return longB64;
        }

        // 5. Hex largo sin prefijo (>= 8 bytes = 16 hex chars)
        if (trimmed.Length >= 16 && TryDecodeHex(trimmed, out var longHex))
            return longHex;

        // 6. Texto UTF-8 directo (conserva "CRIPTOGRAFIA", "clave123", etc.)
        return Encoding.UTF8.GetBytes(trimmed);
    }

    /// <summary>
    /// Resuelve un secreto de longitud fija (por ej. AES/DES/Seed), lanzando CryptographicException descriptiva si es inválido.
    /// </summary>
    public static byte[] ResolveFixedLengthKey(string? input, int expectedBytes, string algorithmLabel)
    {
        if (string.IsNullOrWhiteSpace(input))
            throw new CryptographicException($"[{algorithmLabel}] No se proporcionó llave o semilla secreta.");

        byte[] parsed = ParseRawOrTextKey(input, expectedBytes: expectedBytes, preferBase64WithoutPadding: true);
        if (parsed.Length == expectedBytes)
            return parsed;

        if (TryDecodeFlexibleBase64(input, out var flexB64) && flexB64.Length == expectedBytes)
            return flexB64;

        throw new CryptographicException(
            $"[{algorithmLabel}] Formato o tamaño de secreto incompatible (se esperaban {expectedBytes} bytes, se recibieron {parsed.Length} bytes). " +
            "Si el paquete proviene de otro equipo (p. ej. semilla específica), delega el descifrado al nodo dueño.");
    }

    /// <summary>
    /// Construye todas las interpretaciones posibles de un secreto (para verificación HMAC tolerante entre equipos).
    /// </summary>
    public static List<byte[]> BuildKeyCandidates(string? input)
    {
        var result = new List<byte[]>();
        if (string.IsNullOrEmpty(input))
            return result;

        void AddUnique(byte[] candidate)
        {
            if (candidate.Length == 0) return;
            foreach (var existing in result)
            {
                if (existing.AsSpan().SequenceEqual(candidate))
                    return;
            }
            result.Add(candidate);
        }

        string trimmed = input.Trim();
        if (TryDecodeBase64Strict(trimmed, out var b64Strict))
            AddUnique(b64Strict);
        else if (TryDecodeFlexibleBase64(trimmed, out var b64Flex))
            AddUnique(b64Flex);

        if (TryDecodeHex(trimmed, out var hex))
            AddUnique(hex);

        if (trimmed.Length > 0)
            AddUnique(Encoding.UTF8.GetBytes(trimmed));

        if (!string.Equals(input, trimmed, StringComparison.Ordinal))
            AddUnique(Encoding.UTF8.GetBytes(input));

        return result;
    }

    /// <summary>
    /// Normaliza una llave HMAC para envío v2.0 garantizando Base64 de al menos 32 bytes (requerido por EQ08).
    /// </summary>
    public static string NormalizeHmacKeyBase64(string? secretInput)
    {
        if (string.IsNullOrWhiteSpace(secretInput))
            return string.Empty;

        string trimmed = secretInput.Trim();
        byte[] raw;

        if ((HasExplicitBase64Markers(trimmed) || trimmed.Length >= 40) && TryDecodeBase64Strict(trimmed, out var b64))
        {
            raw = b64;
        }
        else if ((trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase) || trimmed.Length >= 32) && TryDecodeHex(trimmed, out var hex))
        {
            raw = hex;
        }
        else
        {
            raw = Encoding.UTF8.GetBytes(trimmed);
        }

        if (raw.Length < 32)
            raw = SHA256.HashData(raw);

        return Convert.ToBase64String(raw);
    }

    /// <summary>
    /// Parsea un entero entero/desplazamiento desde decimal ("3", "-3"), Base64 (1 o 4 bytes) o Hex.
    /// </summary>
    public static bool TryParseIntegerKey(string? input, out int value)
    {
        value = 0;
        if (string.IsNullOrWhiteSpace(input))
            return false;

        string trimmed = input.Trim();
        if (int.TryParse(trimmed, NumberStyles.Integer, CultureInfo.InvariantCulture, out value))
            return true;

        if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && TryDecodeHex(trimmed, out var hex))
        {
            if (hex.Length == 1) { value = hex[0]; return true; }
            if (hex.Length == 4) { value = BitConverter.ToInt32(hex, 0); return true; }
            if (hex.Length > 0) { value = hex[0]; return true; }
        }

        if (TryDecodeFlexibleBase64(trimmed, out var b64))
        {
            if (b64.Length == 1) { value = b64[0]; return true; }
            if (b64.Length == 4) { value = BitConverter.ToInt32(b64, 0); return true; }
            if (b64.Length > 0) { value = b64[0]; return true; }
        }

        return false;
    }

    public static bool TryGetJsonString(JsonElement root, out string value, params string[] candidateNames)
    {
        value = string.Empty;
        if (root.ValueKind != JsonValueKind.Object)
            return false;

        foreach (string name in candidateNames)
        {
            foreach (var prop in root.EnumerateObject())
            {
                if (!string.Equals(prop.Name, name, StringComparison.OrdinalIgnoreCase))
                    continue;

                if (prop.Value.ValueKind == JsonValueKind.String)
                {
                    value = prop.Value.GetString() ?? string.Empty;
                    return true;
                }
                if (prop.Value.ValueKind is JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False)
                {
                    value = prop.Value.ToString();
                    return true;
                }
            }
        }
        return false;
    }

    public static bool TryGetJsonInt(JsonElement root, out int value, params string[] candidateNames)
    {
        value = 0;
        if (root.ValueKind != JsonValueKind.Object)
            return false;

        foreach (string name in candidateNames)
        {
            foreach (var prop in root.EnumerateObject())
            {
                if (!string.Equals(prop.Name, name, StringComparison.OrdinalIgnoreCase))
                    continue;

                if (prop.Value.ValueKind == JsonValueKind.Number && prop.Value.TryGetInt32(out value))
                    return true;

                if (prop.Value.ValueKind == JsonValueKind.String &&
                    int.TryParse(prop.Value.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out value))
                    return true;
            }
        }
        return false;
    }

    public static bool TryDecodeBase64OrHex(string? input, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(input)) return false;

        string trimmed = input.Trim();
        if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return TryDecodeHex(trimmed, out bytes);

        if (TryDecodeFlexibleBase64(trimmed, out bytes))
            return true;

        return TryDecodeHex(trimmed, out bytes);
    }
}
