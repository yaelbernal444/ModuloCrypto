using ModuloCrypto.Core.Services;
using ModuloCrypto.Security.Strategies;

namespace ModuloCrypto.Security;

/// <summary>
/// Catálogo oficial con EXCLUSIVAMENTE los 21 algoritmos estándar (IDs 1 al 21).
/// </summary>
public static class CryptoCatalog
{
    private static readonly List<ICryptoStrategy> StrategiesList = BuildStrategies();

    private static List<ICryptoStrategy> BuildStrategies()
    {
        var list = new List<ICryptoStrategy>
        {
            new AesGcmStrategy(),         // 1.  AESGCM         (EQ01)
            new DesStrategy(),            // 2.  DES            (EQ01)
            new TripleDesStrategy(),      // 3.  TRIPLEDES      (EQ02)
            new ChaCha20Strategy(),       // 4.  CHACHA20       (EQ02)
            new RsaStrategy(),            // 5.  RSA            (EQ02)
            new EccStrategy(),            // 6.  ECC            (EQ03)
            new DiffieHellmanStrategy(),  // 7.  DIFFIEHELLMAN  (EQ03)
            new CaesarStrategy(),         // 8.  CAESAR         (EQ03)
            new VigenereStrategy(),       // 9.  VIGENERE       (EQ04)
            new XorAsmStrategy(),         // 10. XORASM         (EQ04)
            new LsbStegoStrategy(),       // 11. LSBSTEGO       (EQ04)
            new EuclidesAffineStrategy(), // 12. EUCLIDESAFFINE (EQ05)
            new MillerRabinStrategy(),    // 13. MILLERRABIN    (EQ05)
            new FisherYatesStrategy(),    // 14. FISHERYATES    (EQ05)
            new HashShaStrategy(),        // 15. HASHSHA        (EQ06)
            new HmacSha256Strategy(),     // 16. HMACSHA256     (EQ06)
            new DigitalSigStrategy(),     // 17. DIGITALSIG     (EQ06)
            new QuantumPqcStrategy(),     // 18. QUANTUMPQC     (EQ07)
            new DftSpectralStrategy(),    // 19. DFTSPECTRAL    (EQ07)
            new LagrangeShamirStrategy(), // 20. LAGRANGESHAMIR (EQ08)
            new LorenzSz40Strategy()      // 21. LORENZSZ40     (EQ08)
        };

        for (int i = 0; i < list.Count; i++)
        {
            list[i].Info.AlgorithmId = i + 1;
            list[i].Info.OwnerNode = NodeRuntimeState.GetOwnerNodeForAlgorithm(list[i].Info.Code);
        }

        return list;
    }

    private static readonly Dictionary<string, ICryptoStrategy> StrategyMap =
        StrategiesList.ToDictionary(s => s.Info.Code, StringComparer.OrdinalIgnoreCase);

    private static readonly Dictionary<string, int> AlgorithmIdMap =
        StrategiesList.Select((s, index) => (s.Info.Code, Id: index + 1))
                      .ToDictionary(x => x.Code, x => x.Id, StringComparer.OrdinalIgnoreCase);

    public static IReadOnlyList<CryptoAlgorithmInfo> OfficialAlgorithms { get; } =
        StrategiesList.Select(s => s.Info).ToList();

    public static ICryptoStrategy GetStrategy(string code)
    {
        if (string.IsNullOrWhiteSpace(code) || !StrategyMap.TryGetValue(code.Trim(), out var strategy))
            throw new ArgumentException($"Algoritmo no autorizado o desconocido: '{code}'. Solo se permiten los 21 códigos oficiales.");
        return strategy;
    }

    public static int GetAlgorithmId(string code)
    {
        return !string.IsNullOrWhiteSpace(code) && AlgorithmIdMap.TryGetValue(code.Trim(), out int id) ? id : 1;
    }

    public static CryptoAlgorithmInfo GetAlgorithmById(int id)
    {
        int idx = Math.Clamp(id, 1, StrategiesList.Count) - 1;
        return StrategiesList[idx].Info;
    }

    public static string GetOwnerNode(string code) => NodeRuntimeState.GetOwnerNodeForAlgorithm(code);

    public static bool IsOfficialCode(string code) =>
        !string.IsNullOrWhiteSpace(code) && StrategyMap.ContainsKey(code.Trim());
}
