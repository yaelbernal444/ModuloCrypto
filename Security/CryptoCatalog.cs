using ModuloCrypto.Security.Strategies;

namespace ModuloCrypto.Security;

/// <summary>
/// Catálogo oficial con EXCLUSIVAMENTE los 21 algoritmos estándar de la red ModuloCrypto.
/// </summary>
public static class CryptoCatalog
{
    private static readonly List<ICryptoStrategy> StrategiesList = new()
    {
        new AesGcmStrategy(),         // 1.  AESGCM
        new DesStrategy(),            // 2.  DES
        new TripleDesStrategy(),      // 3.  TRIPLEDES
        new ChaCha20Strategy(),       // 4.  CHACHA20
        new RsaStrategy(),            // 5.  RSA
        new EccStrategy(),            // 6.  ECC
        new DiffieHellmanStrategy(),  // 7.  DIFFIEHELLMAN
        new CaesarStrategy(),         // 8.  CAESAR
        new VigenereStrategy(),       // 9.  VIGENERE
        new XorAsmStrategy(),         // 10. XORASM
        new LsbStegoStrategy(),       // 11. LSBSTEGO
        new EuclidesAffineStrategy(), // 12. EUCLIDESAFFINE
        new MillerRabinStrategy(),    // 13. MILLERRABIN
        new FisherYatesStrategy(),    // 14. FISHERYATES
        new HashShaStrategy(),        // 15. HASHSHA
        new HmacSha256Strategy(),     // 16. HMACSHA256
        new DigitalSigStrategy(),     // 17. DIGITALSIG
        new QuantumPqcStrategy(),     // 18. QUANTUMPQC
        new DftSpectralStrategy(),    // 19. DFTSPECTRAL
        new LagrangeShamirStrategy(), // 20. LAGRANGESHAMIR
        new LorenzSz40Strategy()      // 21. LORENZSZ40
    };

    private static readonly Dictionary<string, ICryptoStrategy> StrategyMap =
        StrategiesList.ToDictionary(s => s.Info.Code, StringComparer.OrdinalIgnoreCase);

    public static IReadOnlyList<CryptoAlgorithmInfo> OfficialAlgorithms { get; } =
        StrategiesList.Select(s => s.Info).ToList();

    public static ICryptoStrategy GetStrategy(string code)
    {
        if (string.IsNullOrWhiteSpace(code) || !StrategyMap.TryGetValue(code.Trim(), out var strategy))
            throw new ArgumentException($"Algoritmo no autorizado o desconocido: '{code}'. Solo se permiten los 21 códigos oficiales.");
        return strategy;
    }

    public static bool IsOfficialCode(string code) =>
        !string.IsNullOrWhiteSpace(code) && StrategyMap.ContainsKey(code.Trim());
}
