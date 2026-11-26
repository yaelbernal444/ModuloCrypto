using System.Collections.Concurrent;

namespace ModuloCrypto.Network.V2;

public sealed class V2CryptoJobRecord
{
    public string JobId { get; init; } = Guid.NewGuid().ToString("D").ToLowerInvariant();
    public string RequestId { get; init; } = string.Empty;
    public string RequesterNode { get; init; } = string.Empty;
    public string Operation { get; init; } = "forward";
    public string AlgorithmCode { get; init; } = "AESGCM";
    public string Status { get; set; } = "running"; // running, completed, failed
    public string? ResultFilePath { get; set; }
    public V2CryptoForwardResponse? ForwardResult { get; set; }
    public string? ErrorCode { get; set; }
    public string? ErrorDetail { get; set; }
    public DateTime CreatedAtUtc { get; init; } = DateTime.UtcNow;
    public DateTime? CompletedAtUtc { get; set; }
}

/// <summary>
/// Administrador de trabajos asíncronos v2.0 (GET /api/jobs/{jobId} y GET /api/jobs/{jobId}/result)
/// con retención mínima de 1 hora y verificación de propiedad X-CC-Node == requesterNode.
/// </summary>
public static class V2CryptoJobManager
{
    private static readonly ConcurrentDictionary<string, V2CryptoJobRecord> Jobs = new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan RetentionPeriod = TimeSpan.FromHours(1.5);

    public static V2CryptoJobRecord EnqueueJob(
        string requestId,
        string requesterNode,
        string operation,
        string algorithmCode,
        Func<Task<(V2CryptoForwardResponse? ForwardRes, string? ResultZipPath)>> work)
    {
        PurgeExpiredJobs();

        var job = new V2CryptoJobRecord
        {
            JobId = Guid.NewGuid().ToString("D").ToLowerInvariant(),
            RequestId = requestId,
            RequesterNode = requesterNode,
            Operation = operation,
            AlgorithmCode = algorithmCode,
            Status = "running",
            CreatedAtUtc = DateTime.UtcNow
        };

        Jobs[job.JobId] = job;

        _ = Task.Run(async () =>
        {
            try
            {
                var (fwd, zipPath) = await work();
                job.ForwardResult = fwd;
                job.ResultFilePath = zipPath;
                job.Status = "completed";
                job.CompletedAtUtc = DateTime.UtcNow;
            }
            catch (ModuloCrypto.Core.Contracts.PacketValidationException pve)
            {
                job.Status = "failed";
                job.ErrorCode = pve.ErrorCode;
                job.ErrorDetail = pve.Message;
                job.CompletedAtUtc = DateTime.UtcNow;
            }
            catch (Exception ex)
            {
                job.Status = "failed";
                job.ErrorCode = "E-INTERNAL";
                job.ErrorDetail = ex.Message;
                job.CompletedAtUtc = DateTime.UtcNow;
            }
        });

        return job;
    }

    public static V2CryptoJobRecord? GetJob(string jobId)
    {
        PurgeExpiredJobs();
        return Jobs.TryGetValue(jobId, out var job) ? job : null;
    }

    private static void PurgeExpiredJobs()
    {
        DateTime cutoff = DateTime.UtcNow - RetentionPeriod;
        foreach (var kv in Jobs.ToArray())
        {
            if (kv.Value.CreatedAtUtc < cutoff)
            {
                Jobs.TryRemove(kv.Key, out _);
            }
        }
    }
}
