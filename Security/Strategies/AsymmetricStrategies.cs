using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ModuloCrypto.Security.Strategies;

/// <summary>5. RSA — RSA-OAEP / RSA-PSS (envoltura híbrida para archivos arbitrarios)</summary>
public sealed class RsaStrategy : ICryptoStrategy
{
    public CryptoAlgorithmInfo Info { get; } = new()
    {
        Code = "RSA",
        DisplayName = "RSA-OAEP / RSA-PSS",
        Category = "Asimétrico",
        Description = "Cifrado híbrido RSA-2048 OAEP-SHA256 con firma RSA-PSS y protección de sesión AES-GCM."
    };

    public CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase = null)
    {
        using var rsa = RSA.Create(2048);
        byte[] sessionKey = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] cipher = new byte[plainBytes.Length];
        byte[] tag = new byte[16];

        using (var aes = new AesGcm(sessionKey, 16))
            aes.Encrypt(nonce, plainBytes, cipher, tag);

        byte[] wrappedKey = rsa.Encrypt(sessionKey, RSAEncryptionPadding.OaepSHA256);
        byte[] signature = rsa.SignData(cipher, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        string pubJson = JsonSerializer.Serialize(new
        {
            mode = "RSA-2048-OAEP-PSS",
            publicKey = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo()),
            wrappedKey = Convert.ToBase64String(wrappedKey),
            nonce = Convert.ToBase64String(nonce),
            tag = Convert.ToBase64String(tag),
            signaturePss = Convert.ToBase64String(signature)
        });

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = cipher,
            SecretKeyBase64 = Convert.ToBase64String(rsa.ExportPkcs8PrivateKey()),
            PublicParametersJson = pubJson,
            Summary = $"RSA-2048 OAEP + firma PSS generada ({cipher.Length} bytes)."
        };
    }

    public CryptoOperationResult Decrypt(byte[] cipherBytes, string secretKeyBase64, string publicParametersJson)
    {
        using var doc = JsonDocument.Parse(publicParametersJson);
        using var rsa = RSA.Create();

        byte[] privKeyBytes = DecodeAsymmetricKey(secretKeyBase64, "RSA privada");
        rsa.ImportPkcs8PrivateKey(privKeyBytes, out _);

        byte[] wrappedKey = DecodePubParamField(doc.RootElement, "wrappedKey", "RSA");
        byte[] nonce = DecodePubParamField(doc.RootElement, "nonce", "RSA");
        byte[] tag = DecodePubParamField(doc.RootElement, "tag", "RSA");
        byte[] sig = DecodePubParamField(doc.RootElement, "signaturePss", "RSA");

        bool sigOk = rsa.VerifyData(cipherBytes, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        if (!sigOk)
            throw new CryptographicException("Firma RSA-PSS inválida.");

        byte[] sessionKey = rsa.Decrypt(wrappedKey, RSAEncryptionPadding.OaepSHA256);
        byte[] plain = new byte[cipherBytes.Length];
        using (var aes = new AesGcm(sessionKey, 16))
            aes.Decrypt(nonce, cipherBytes, tag, plain);

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = plain,
            SecretKeyBase64 = secretKeyBase64,
            PublicParametersJson = publicParametersJson,
            Summary = $"RSA-2048 PSS verificado y descifrado ({plain.Length} bytes)."
        };
    }

    internal static byte[] DecodeAsymmetricKey(string? rawInput, string label)
    {
        if (string.IsNullOrWhiteSpace(rawInput))
            throw new CryptographicException($"Llave {label} vacía.");

        string body = rawInput.Trim();
        if (body.Contains("-----BEGIN", StringComparison.OrdinalIgnoreCase))
        {
            var sb = new System.Text.StringBuilder(body.Length);
            foreach (string line in body.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string t = line.Trim();
                if (!t.StartsWith("-----", StringComparison.Ordinal))
                    sb.Append(t);
            }
            body = sb.ToString();
        }

        if (KeyInputParser.TryDecodeBase64OrHex(body, out byte[] decoded) && decoded.Length > 0)
            return decoded;

        throw new CryptographicException($"Formato inválido en llave {label}: se esperaba Base64, PEM o Hex válido.");
    }

    internal static byte[] DecodePubParamField(JsonElement root, string fieldName, string algLabel)
    {
        if (!KeyInputParser.TryGetJsonString(root, out string rawVal, fieldName) || string.IsNullOrWhiteSpace(rawVal))
            throw new CryptographicException($"Falta parámetro público '{fieldName}' en {algLabel}.");

        if (KeyInputParser.TryDecodeBase64OrHex(rawVal, out byte[] bytes) && bytes.Length > 0)
            return bytes;

        throw new CryptographicException($"Parámetro público '{fieldName}' de {algLabel} no tiene Base64/Hex válido.");
    }
}

/// <summary>6. ECC — ECDH / ECDSA (NIST P-256)</summary>
public sealed class EccStrategy : ICryptoStrategy
{
    public CryptoAlgorithmInfo Info { get; } = new()
    {
        Code = "ECC",
        DisplayName = "ECDH / ECDSA",
        Category = "Asimétrico Curva Elíptica",
        Description = "Intercambio efímero ECDH P-256 + cifrado autenticado + firma ECDSA."
    };

    public CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase = null)
    {
        using var sender = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var receiver = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        byte[] sharedKey = sender.DeriveKeyFromHash(receiver.PublicKey, HashAlgorithmName.SHA256);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] cipher = new byte[plainBytes.Length];
        byte[] tag = new byte[16];

        using (var aes = new AesGcm(sharedKey, 16))
            aes.Encrypt(nonce, plainBytes, cipher, tag);

        byte[] signature = signer.SignData(cipher, HashAlgorithmName.SHA256);

        string pubJson = JsonSerializer.Serialize(new
        {
            curve = "NIST-P256",
            ephemeralSenderPub = Convert.ToBase64String(sender.PublicKey.ExportSubjectPublicKeyInfo()),
            ecdsaPub = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo()),
            ecdsaSig = Convert.ToBase64String(signature),
            nonce = Convert.ToBase64String(nonce),
            tag = Convert.ToBase64String(tag)
        });

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = cipher,
            SecretKeyBase64 = Convert.ToBase64String(receiver.ExportPkcs8PrivateKey()),
            PublicParametersJson = pubJson,
            Summary = $"ECC (ECDH P-256 + ECDSA) cifrado ({cipher.Length} bytes)."
        };
    }

    public CryptoOperationResult Decrypt(byte[] cipherBytes, string secretKeyBase64, string publicParametersJson)
    {
        using var doc = JsonDocument.Parse(publicParametersJson);
        byte[] senderPubBytes = RsaStrategy.DecodePubParamField(doc.RootElement, "ephemeralSenderPub", "ECC");
        byte[] ecdsaPubBytes = RsaStrategy.DecodePubParamField(doc.RootElement, "ecdsaPub", "ECC");
        byte[] sig = RsaStrategy.DecodePubParamField(doc.RootElement, "ecdsaSig", "ECC");
        byte[] nonce = RsaStrategy.DecodePubParamField(doc.RootElement, "nonce", "ECC");
        byte[] tag = RsaStrategy.DecodePubParamField(doc.RootElement, "tag", "ECC");

        using (var verifier = ECDsa.Create())
        {
            verifier.ImportSubjectPublicKeyInfo(ecdsaPubBytes, out _);
            if (!verifier.VerifyData(cipherBytes, sig, HashAlgorithmName.SHA256))
                throw new CryptographicException("Firma ECDSA P-256 inválida.");
        }

        using var receiver = ECDiffieHellman.Create();
        receiver.ImportPkcs8PrivateKey(RsaStrategy.DecodeAsymmetricKey(secretKeyBase64, "ECC privada"), out _);
        using var senderPub = ECDiffieHellman.Create();
        senderPub.ImportSubjectPublicKeyInfo(senderPubBytes, out _);

        byte[] sharedKey = receiver.DeriveKeyFromHash(senderPub.PublicKey, HashAlgorithmName.SHA256);
        byte[] plain = new byte[cipherBytes.Length];
        using (var aes = new AesGcm(sharedKey, 16))
            aes.Decrypt(nonce, cipherBytes, tag, plain);

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = plain,
            SecretKeyBase64 = secretKeyBase64,
            PublicParametersJson = publicParametersJson,
            Summary = $"ECC (ECDH + ECDSA) verificado y descifrado ({plain.Length} bytes)."
        };
    }
}

/// <summary>7. DIFFIEHELLMAN — Diffie-Hellman modular clásico</summary>
public sealed class DiffieHellmanStrategy : ICryptoStrategy
{
    // RFC 3526 Group 5 (1536-bit MODP prime, compact hex)
    private static readonly BigInteger SafePrime = BigInteger.Parse(
        "00FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
        "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
        System.Globalization.NumberStyles.HexNumber);

    private static readonly BigInteger Generator = 2;

    public CryptoAlgorithmInfo Info { get; } = new()
    {
        Code = "DIFFIEHELLMAN",
        DisplayName = "Diffie-Hellman",
        Category = "Intercambio de Llaves",
        Description = "Acuerdo de llave Diffie-Hellman MODP (1536-bit) derivando clave de sesión SHA-256 + AES-GCM."
    };

    public CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase = null)
    {
        BigInteger a = GenerateRandomExponent();
        BigInteger b = GenerateRandomExponent();
        BigInteger pubA = BigInteger.ModPow(Generator, a, SafePrime);
        BigInteger pubB = BigInteger.ModPow(Generator, b, SafePrime);
        BigInteger shared = BigInteger.ModPow(pubB, a, SafePrime);

        byte[] key = SHA256.HashData(shared.ToByteArray(isUnsigned: true, isBigEndian: true));
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] cipher = new byte[plainBytes.Length];
        byte[] tag = new byte[16];

        using (var aes = new AesGcm(key, 16))
            aes.Encrypt(nonce, plainBytes, cipher, tag);

        string pubJson = JsonSerializer.Serialize(new
        {
            group = "RFC3526-MODP-1536",
            g = 2,
            pubA = Convert.ToBase64String(pubA.ToByteArray(true, true)),
            pubB = Convert.ToBase64String(pubB.ToByteArray(true, true)),
            nonce = Convert.ToBase64String(nonce),
            tag = Convert.ToBase64String(tag)
        });

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = cipher,
            SecretKeyBase64 = Convert.ToBase64String(b.ToByteArray(true, true)),
            PublicParametersJson = pubJson,
            Summary = $"Diffie-Hellman MODP-1536 acordado y cifrado ({cipher.Length} bytes)."
        };
    }

    public CryptoOperationResult Decrypt(byte[] cipherBytes, string secretKeyBase64, string publicParametersJson)
    {
        using var doc = JsonDocument.Parse(publicParametersJson);
        BigInteger pubA = new BigInteger(RsaStrategy.DecodePubParamField(doc.RootElement, "pubA", "DH"), true, true);
        BigInteger privB = new BigInteger(RsaStrategy.DecodeAsymmetricKey(secretKeyBase64, "Diffie-Hellman privada"), true, true);
        byte[] nonce = RsaStrategy.DecodePubParamField(doc.RootElement, "nonce", "DH");
        byte[] tag = RsaStrategy.DecodePubParamField(doc.RootElement, "tag", "DH");

        BigInteger shared = BigInteger.ModPow(pubA, privB, SafePrime);
        byte[] key = SHA256.HashData(shared.ToByteArray(true, true));
        byte[] plain = new byte[cipherBytes.Length];

        using (var aes = new AesGcm(key, 16))
            aes.Decrypt(nonce, cipherBytes, tag, plain);

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = plain,
            SecretKeyBase64 = secretKeyBase64,
            PublicParametersJson = publicParametersJson,
            Summary = $"Diffie-Hellman secreto compartido recalculado y descifrado ({plain.Length} bytes)."
        };
    }

    private static BigInteger GenerateRandomExponent()
    {
        byte[] bytes = RandomNumberGenerator.GetBytes(32);
        return new BigInteger(bytes, isUnsigned: true, isBigEndian: true) + 3;
    }
}

/// <summary>17. DIGITALSIG — Firma Digital RSA-PSS</summary>
public sealed class DigitalSigStrategy : ICryptoStrategy
{
    public CryptoAlgorithmInfo Info { get; } = new()
    {
        Code = "DIGITALSIG",
        DisplayName = "Firma Digital RSA-PSS",
        Category = "Autenticidad / Firma",
        Description = "Firma digital criptográfica RSA-2048 PSS (SHA-256) con verificación de integridad.",
        IsReversible = true
    };

    public CryptoOperationResult Encrypt(byte[] plainBytes, string? optionalPassphrase = null)
    {
        using var rsa = RSA.Create(2048);
        byte[] signature = rsa.SignData(plainBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        // Envolvemos [4 bytes longitud firma][firma][payload original] para transporte íntegro
        byte[] envelope = new byte[4 + signature.Length + plainBytes.Length];
        BitConverter.GetBytes(signature.Length).CopyTo(envelope, 0);
        Buffer.BlockCopy(signature, 0, envelope, 4, signature.Length);
        Buffer.BlockCopy(plainBytes, 0, envelope, 4 + signature.Length, plainBytes.Length);

        string pubJson = JsonSerializer.Serialize(new
        {
            scheme = "RSA-2048-PSS-SHA256",
            signatureBase64 = Convert.ToBase64String(signature),
            publicKey = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo())
        });

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = envelope,
            SecretKeyBase64 = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo()),
            PublicParametersJson = pubJson,
            Summary = $"Paquete firmado con RSA-PSS (firma {signature.Length} bytes + payload)."
        };
    }

    public CryptoOperationResult Decrypt(byte[] cipherBytes, string secretKeyBase64, string publicParametersJson)
    {
        using var doc = JsonDocument.Parse(publicParametersJson);
        byte[] pubKey = KeyInputParser.TryGetJsonString(doc.RootElement, out string pubPemOrB64, "publicKey", "publicKeyPem") &&
                        !string.IsNullOrWhiteSpace(pubPemOrB64)
            ? RsaStrategy.DecodeAsymmetricKey(pubPemOrB64, "DIGITALSIG pública")
            : (!string.IsNullOrWhiteSpace(secretKeyBase64)
                ? RsaStrategy.DecodeAsymmetricKey(secretKeyBase64, "DIGITALSIG pública")
                : throw new CryptographicException("Falta publicKey en publicParameters de DIGITALSIG."));

        byte[] signature;
        byte[] payload;
        int sigLen = cipherBytes.Length >= 4 ? BitConverter.ToInt32(cipherBytes, 0) : -1;
        if (sigLen is >= 64 and <= 1024 && 4 + sigLen <= cipherBytes.Length)
        {
            signature = cipherBytes[4..(4 + sigLen)];
            payload = cipherBytes[(4 + sigLen)..];
        }
        else if (KeyInputParser.TryGetJsonString(doc.RootElement, out string sigB64, "signatureBase64", "signature") &&
                 KeyInputParser.TryDecodeFlexibleBase64(sigB64, out byte[] detachedSig))
        {
            signature = detachedSig;
            payload = cipherBytes;
        }
        else
        {
            throw new CryptographicException("Formato de firma digital DIGITALSIG incompatible.");
        }

        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(pubKey, out _);
        bool valid = rsa.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        if (!valid)
            throw new CryptographicException("La firma digital RSA-PSS NO es válida.");

        return new CryptoOperationResult
        {
            AlgorithmCode = Info.Code,
            OutputBytes = payload,
            SecretKeyBase64 = secretKeyBase64,
            PublicParametersJson = publicParametersJson,
            Summary = $"Firma RSA-PSS VÁLIDA — payload íntegro recuperado ({payload.Length} bytes)."
        };
    }
}
