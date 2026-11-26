using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModuloCrypto.Core.Contracts;
using ModuloCrypto.Core.Data;
using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using ModuloCrypto.Security;
using System.Globalization;

namespace ModuloCrypto.Network;

/// <summary>
/// Servidor ASP.NET Core Minimal API embebido conforme al Estándar de Comunicación v2.0 (EQ01, puerto 5001):
/// - GET  /api/status
/// - GET  /api/certificate
/// - GET  /api/algorithms
/// - POST /api/requests/receive
/// - POST /api/results/receive
/// Incluye validación estricta de 3 archivos ZIP, Anti-ZIP-Bomb, TOFU (403 E-CERT-UNTRUSTED) y Anti-Replay (409 E-REPLAY).
/// </summary>
public sealed class ApiHostService : IAsyncDisposable
{
    private const long MaxRequestSizeBytes = 50L * 1024L * 1024L; // 50 MB estrictos (413 E-SIZE)
    private static readonly TimeSpan ReplayTimestampWindow = TimeSpan.FromMinutes(15);

    private WebApplication? _app;
    private CancellationTokenSource? _cts;

    public async Task StartAsync(int port = 5001)
    {
        try
        {
            _cts = new CancellationTokenSource();
            var builder = WebApplication.CreateBuilder();
            builder.Logging.ClearProviders();

            builder.WebHost.ConfigureKestrel(options =>
            {
                options.Limits.MaxRequestBodySize = MaxRequestSizeBytes + (1024 * 1024); // margen multipart para devolver 413 controlado
            });

            builder.Services.Configure<FormOptions>(options =>
            {
                options.MultipartBodyLengthLimit = MaxRequestSizeBytes + (1024 * 1024);
                options.ValueLengthLimit = int.MaxValue;
            });

            builder.Services.AddCors(options =>
            {
                options.AddDefaultPolicy(policy =>
                    policy.AllowAnyOrigin()
                        .AllowAnyMethod()
                        .AllowAnyHeader());
            });

            builder.WebHost.UseUrls($"http://0.0.0.0:{port}");

            _app = builder.Build();
            _app.UseCors();

            // 1. GET /api/status (Estándar v2.0)
            _app.MapGet("/api/status", () => Results.Ok(new PeerStatusResponse
            {
                NodeId = NodeRuntimeState.CurrentNodeId,
                TeamNumber = NodeRuntimeState.TeamNumber,
                ProtocolVersion = "2.0",
                Status = "online",
                AcceptingPackages = true,
                HttpPort = port,
                HttpsPort = NodeRuntimeState.HttpsPort,
                Algorithms = NodeRuntimeState.OwnedAlgorithms.ToList(),
                CertificateThumbprintSha256 = NodeCertificateService.GetThumbprintSha256Hex(),
                TimestampUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
            }));

            // 2. GET /api/certificate (Estándar v2.0)
            _app.MapGet("/api/certificate", () =>
            {
                var cert = NodeCertificateService.CurrentCertificate;
                return Results.Ok(new PeerCertificateResponse
                {
                    NodeId = NodeRuntimeState.CurrentNodeId,
                    CertificatePem = NodeCertificateService.ExportPublicCertPem(),
                    CertificateThumbprintSha256 = NodeCertificateService.GetThumbprintSha256Hex(),
                    Subject = cert.Subject,
                    NotBeforeUtc = cert.NotBefore.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
                    NotAfterUtc = cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                });
            });

            // 3. GET /api/algorithms (Catálogo oficial de 21 algoritmos con dueño EQ01–EQ08)
            _app.MapGet("/api/algorithms", () => Results.Ok(CryptoCatalog.OfficialAlgorithms));

            // 4. POST /api/requests/receive (Recepción de paquetes 'package' v2.0)
            _app.MapPost("/api/requests/receive", async (HttpRequest request) =>
                await ProcessIncomingZipAsync(request, expectedPacketType: "package"));

            // 5. POST /api/results/receive (Recepción de paquetes 'result' v2.0)
            _app.MapPost("/api/results/receive", async (HttpRequest request) =>
                await ProcessIncomingZipAsync(request, expectedPacketType: "result"));

            await _app.StartAsync(_cts.Token);
            NodeRuntimeState.ApiPort = port;
            NodeRuntimeState.ApiOnline = true;
        }
        catch
        {
            NodeRuntimeState.ApiOnline = false;
        }
    }

    private static async Task<IResult> ProcessIncomingZipAsync(HttpRequest request, string expectedPacketType)
    {
        if (request.ContentLength.HasValue && request.ContentLength.Value > MaxRequestSizeBytes)
        {
            return BuildErrorResult("E-SIZE", StatusCodes.Status413PayloadTooLarge, "El paquete .zip excede el límite máximo de 50 MB.");
        }

        string incomingDir = Path.Combine(AppContext.BaseDirectory, "IncomingPackets");
        Directory.CreateDirectory(incomingDir);

        string fileName = $"incoming_{DateTime.UtcNow:yyyyMMdd_HHmmss}_{Guid.NewGuid():N}.zip";
        string zipPath = Path.Combine(incomingDir, fileName);

        try
        {
            if (request.HasFormContentType && request.Form.Files.Count > 0)
            {
                var file = request.Form.Files.GetFile("package")
                           ?? request.Form.Files.GetFile("file")
                           ?? request.Form.Files[0];

                if (file.Length > MaxRequestSizeBytes)
                {
                    return BuildErrorResult("E-SIZE", StatusCodes.Status413PayloadTooLarge, "El archivo adjunto excede el límite de 50 MB.");
                }

                if (!string.IsNullOrWhiteSpace(file.FileName))
                    fileName = Path.GetFileName(file.FileName);

                zipPath = Path.Combine(incomingDir, $"{Guid.NewGuid().ToString("N")[..8]}_{fileName}");
                await using var fs = File.Create(zipPath);
                await file.CopyToAsync(fs);
            }
            else
            {
                await using var fs = File.Create(zipPath);
                await request.Body.CopyToAsync(fs);
                if (fs.Length > MaxRequestSizeBytes)
                {
                    fs.Close();
                    TryDeleteFile(zipPath);
                    return BuildErrorResult("E-SIZE", StatusCodes.Status413PayloadTooLarge, "El flujo recibido excede el límite de 50 MB.");
                }
            }

            // 1. Validar estructura estricta .zip v2.0, hashes y firma RSA-PSS-SHA256 de 11 campos
            var parsed = PacketZipService.ReadPacketZip(zipPath, enforceStrictSignature: true);
            var manifest = parsed.Manifest;

            if (!string.Equals(manifest.PacketType, expectedPacketType, StringComparison.OrdinalIgnoreCase))
            {
                TryDeleteFile(zipPath);
                return BuildErrorResult(
                    "E-ZIP-STRUCTURE",
                    StatusCodes.Status400BadRequest,
                    $"Este endpoint requiere packetType='{expectedPacketType}', recibido '{manifest.PacketType}'.");
            }

            // 2. Validar ventana de tiempo del timestampUtc
            if (!DateTime.TryParse(
                    manifest.TimestampUtc,
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal,
                    out DateTime packetTimeUtc))
            {
                TryDeleteFile(zipPath);
                return BuildErrorResult("E-TIMESTAMP", StatusCodes.Status400BadRequest, "Formato timestampUtc inválido (se requiere ISO-8601 UTC).");
            }

            if (Math.Abs((DateTime.UtcNow - packetTimeUtc).TotalMinutes) > ReplayTimestampWindow.TotalMinutes)
            {
                TryDeleteFile(zipPath);
                return BuildErrorResult("E-TIMESTAMP", StatusCodes.Status400BadRequest, "El paquete está fuera de la ventana temporal permitida.");
            }

            // 3. Validación TOFU (Trust On First Use): verificar huella contra el directorio de nodos
            var knownPeer = NodeRuntimeState.NetworkPeers.FirstOrDefault(p =>
                p.NodeId.Equals(manifest.SourceNode, StringComparison.OrdinalIgnoreCase));

            if (knownPeer != null)
            {
                NodeNetworkClient.ApplyTofuThumbprintCheck(knownPeer, manifest.CertificateThumbprintSha256);
                if (knownPeer.HasThumbprintMismatch || string.Equals(knownPeer.Status, "blocked", StringComparison.OrdinalIgnoreCase))
                {
                    AppDbContext.UpsertTrustedPeer(knownPeer);
                    NodeRuntimeState.NotifyPeerChanged(knownPeer);
                    TryDeleteFile(zipPath);
                    return BuildErrorResult(
                        "E-CERT-UNTRUSTED",
                        StatusCodes.Status403Forbidden,
                        $"Huella X.509 de {manifest.SourceNode} no coincide con la huella fijada (TOFU).");
                }
            }

            // 4. Protección Anti-Replay en SQLite (SeenPackets)
            using (var db = new AppDbContext())
            {
                string normPacketId = manifest.PacketId.Trim().ToLowerInvariant();
                if (db.SeenPackets.Any(sp => sp.PacketId == normPacketId))
                {
                    TryDeleteFile(zipPath);
                    return BuildErrorResult(
                        "E-REPLAY",
                        StatusCodes.Status409Conflict,
                        $"El packetId '{normPacketId}' ya fue procesado anteriormente (Anti-Replay).");
                }

                db.SeenPackets.Add(new SeenPacketEntity
                {
                    PacketId = normPacketId,
                    SourceNode = manifest.SourceNode,
                    PacketTimestampUtc = packetTimeUtc,
                    ReceivedAtUtc = DateTime.UtcNow
                });

                string ipOrigen = request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? manifest.SourceIp;

                var solicitud = new SolicitudEntrante
                {
                    PacketId = normPacketId,
                    NodoOrigen = manifest.SourceNode,
                    IpOrigen = ipOrigen,
                    NombreZip = fileName,
                    AlgoritmoCodigo = manifest.AlgorithmCode,
                    FirmaX509Valida = parsed.SignatureValid && parsed.IntegrityValid,
                    RutaZipTemporal = zipPath,
                    Estado = "Pendiente",
                    FechaRecepcion = DateTime.Now
                };

                db.SolicitudesEntrantes.Add(solicitud);
                await db.SaveChangesAsync();

                NodeRuntimeState.NotifyPacketReceived(solicitud);

                return Results.Accepted($"/api/requests/{solicitud.Id}", new
                {
                    requestId = solicitud.Id,
                    packetId = solicitud.PacketId,
                    packetType = manifest.PacketType,
                    status = "Pendiente",
                    zipFileName = fileName,
                    algorithmCode = solicitud.AlgoritmoCodigo,
                    signatureValid = solicitud.FirmaX509Valida,
                    receiverNode = NodeRuntimeState.CurrentNodeId,
                    timestampUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
                });
            }
        }
        catch (PacketValidationException pvEx)
        {
            TryDeleteFile(zipPath);
            return BuildErrorResult(pvEx.ErrorCode, pvEx.HttpStatusCode, pvEx.Message);
        }
        catch (Exception ex)
        {
            TryDeleteFile(zipPath);
            return BuildErrorResult("E-INTERNAL", StatusCodes.Status400BadRequest, ex.Message);
        }
    }

    private static IResult BuildErrorResult(string errorCode, int statusCode, string message)
    {
        return Results.Json(
            new StandardErrorResponse
            {
                ErrorCode = errorCode,
                Message = message,
                NodeId = NodeRuntimeState.CurrentNodeId,
                TimestampUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
            },
            statusCode: statusCode);
    }

    private static void TryDeleteFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return;
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }

    public async ValueTask DisposeAsync()
    {
        if (_app != null)
        {
            try
            {
                await _app.StopAsync(TimeSpan.FromSeconds(2));
                await _app.DisposeAsync();
            }
            catch { }
        }
        _cts?.Dispose();
        NodeRuntimeState.ApiOnline = false;
    }
}
