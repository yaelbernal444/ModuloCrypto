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
using ModuloCrypto.Security.Strategies;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace ModuloCrypto.Network.V2;

/// <summary>
/// Servidor ASP.NET Core Minimal API embebido conforme al Estándar de Comunicación v2.0 (Sección 5, 6, 10, 12, 13, 14):
/// - GET  /api/status
/// - GET  /api/certificate (application/x-pem-file)
/// - GET  /api/algorithms (perfil Sección 10.4 para los algoritmos de este equipo, ej. AESGCM y DES en EQ01)
/// - POST /api/requests/receive (campo package -> 202 Accepted { packetId, status, receivedAtUtc }, validación de 14 pasos + TOFU)
/// - POST /api/results/receive (campo package -> 202 Accepted)
/// - POST /api/crypto/forward (multipart/form-data: request, requestSignature sobre bytes crudos, requesterCertificate, payload)
/// - POST /api/crypto/inverse (devuelve .zip tipo result con resultado.enc cifrado con CC-ENV-1 y resultEnvelope sin ciphertextBase64)
/// - GET  /api/jobs/{jobId} y GET /api/jobs/{jobId}/result (retención >= 1h, verifica X-CC-Node == requesterNode)
/// - GET  /api/keys/{keyId} (almacén AsymmetricKeys en SQLite con privadas protegidas por DPAPI)
/// Todas las respuestas de error cumplen RFC 9457 (application/problem+json).
/// </summary>
public sealed class V2ApiHostService : IAsyncDisposable
{
    private const long MaxRequestSizeBytes = 50L * 1024L * 1024L; // 52,428,800 B (50 MB)
    private static readonly SemaphoreSlim CryptoConcurrencyGate = new(10, 10); // máx 10 peticiones simultáneas -> 503 E-BUSY
    private static readonly TimeSpan SyncCryptoTimeout = TimeSpan.FromSeconds(30);
    private static readonly byte[] AsymmetricDpapiEntropy = Encoding.UTF8.GetBytes("ModuloCrypto.AsymmetricKeys.DPAPI.v2");

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private WebApplication? _app;
    private CancellationTokenSource? _cts;

    public string LastStartupError { get; private set; } = string.Empty;

    public async Task<bool> StartAsync(int port = 5001)
    {
        try
        {
            LastStartupError = string.Empty;
            _cts = new CancellationTokenSource();
            var builder = WebApplication.CreateBuilder();
            builder.Logging.ClearProviders();

            builder.WebHost.ConfigureKestrel(options =>
            {
                options.Limits.MaxRequestBodySize = MaxRequestSizeBytes + (2 * 1024 * 1024);
            });

            builder.Services.Configure<FormOptions>(options =>
            {
                options.MultipartBodyLengthLimit = MaxRequestSizeBytes + (2 * 1024 * 1024);
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

            // 1. GET /api/status (Sección 10.3)
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
                CertificateThumbprintSha256 = V2CertificateService.GetThumbprintSha256Hex(),
                TimestampUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
            }));

            // 2. GET /api/certificate (application/x-pem-file conforme a Sección 5.5)
            _app.MapGet("/api/certificate", (HttpRequest req) =>
            {
                string pem = V2CertificateService.ExportPublicCertPem();
                string accept = req.Headers.Accept.ToString();
                if (accept.Contains("application/json", StringComparison.OrdinalIgnoreCase) &&
                    !accept.Contains("application/x-pem-file", StringComparison.OrdinalIgnoreCase))
                {
                    var cert = V2CertificateService.CurrentCertificate;
                    return Results.Ok(new PeerCertificateResponse
                    {
                        NodeId = NodeRuntimeState.CurrentNodeId,
                        CertificatePem = pem,
                        CertificateThumbprintSha256 = V2CertificateService.GetThumbprintSha256Hex(),
                        Subject = cert.Subject,
                        NotBeforeUtc = cert.NotBefore.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
                        NotAfterUtc = cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                    });
                }

                return Results.Text(pem, "application/x-pem-file", Encoding.UTF8);
            });

            // 3. GET /api/algorithms (Sección 10.4)
            _app.MapGet("/api/algorithms", () => Results.Ok(BuildOwnedAlgorithmProfiles()));

            // 4. POST /api/requests/receive (campo 'package', validación de 14 pasos, devuelve 202 Accepted)
            _app.MapPost("/api/requests/receive", async (HttpRequest request) =>
                await ProcessIncomingZipAsync(request, expectedPacketType: "package"));

            // 5. POST /api/results/receive (campo 'package', packetType = "result", devuelve 202 Accepted)
            _app.MapPost("/api/results/receive", async (HttpRequest request) =>
                await ProcessIncomingZipAsync(request, expectedPacketType: "result"));

            // 6. POST /api/crypto/forward
            _app.MapPost("/api/crypto/forward", async (HttpRequest request) =>
                await HandleCryptoForwardEndpointAsync(request));

            // 7. POST /api/crypto/inverse
            _app.MapPost("/api/crypto/inverse", async (HttpRequest request) =>
                await HandleCryptoInverseEndpointAsync(request));

            // 8. GET /api/jobs/{jobId}
            _app.MapGet("/api/jobs/{jobId}", (string jobId, HttpRequest request) =>
                HandleGetJobStatus(jobId, request));

            // 9. GET /api/jobs/{jobId}/result
            _app.MapGet("/api/jobs/{jobId}/result", (string jobId, HttpRequest request) =>
                HandleGetJobResult(jobId, request));

            // 10. GET /api/keys/{keyId}
            _app.MapGet("/api/keys/{keyId}", (string keyId) =>
                HandleGetAsymmetricPublicKey(keyId));

            await _app.StartAsync(_cts.Token);
            NodeRuntimeState.ApiPort = port;
            NodeRuntimeState.ApiOnline = true;
            return true;
        }
        catch (Exception ex)
        {
            LastStartupError = ex.Message;
            NodeRuntimeState.ApiOnline = false;
            return false;
        }
    }

    public static List<V2AlgorithmProfileDto> BuildOwnedAlgorithmProfiles()
    {
        var profiles = new List<V2AlgorithmProfileDto>();
        foreach (string code in NodeRuntimeState.OwnedAlgorithms)
        {
            var info = CryptoCatalog.GetStrategy(code).Info;
            var schema = code.ToUpperInvariant() switch
            {
                "AESGCM" => new List<string> { "keySizeBits", "nonceBase64", "tagBase64" },
                "DES" => new List<string> { "mode", "padding", "ivBase64" },
                _ => new List<string> { "mode", "parameters" }
            };

            profiles.Add(new V2AlgorithmProfileDto
            {
                AlgorithmId = CryptoCatalog.GetAlgorithmId(code),
                AlgorithmCode = info.Code,
                AlgorithmName = info.DisplayName,
                OwnerNode = NodeRuntimeState.CurrentNodeId,
                Category = info.Category,
                Operations = info.IsReversible ? new List<string> { "forward", "inverse" } : new List<string> { "forward" },
                RequiresKeyEnvelope = true,
                PublicParametersSchema = schema,
                Description = info.Description
            });
        }
        return profiles;
    }

    private static async Task<IResult> ProcessIncomingZipAsync(HttpRequest request, string expectedPacketType)
    {
        if (request.ContentLength.HasValue && request.ContentLength.Value > MaxRequestSizeBytes)
        {
            return V2ProblemDetails.ToResult("E-SIZE", StatusCodes.Status413PayloadTooLarge,
                "El paquete .zip excede el límite máximo de 50 MB.", request.Path);
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
                    return V2ProblemDetails.ToResult("E-SIZE", StatusCodes.Status413PayloadTooLarge,
                        "El archivo adjunto excede el límite de 50 MB.", request.Path);
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
                    return V2ProblemDetails.ToResult("E-SIZE", StatusCodes.Status413PayloadTooLarge,
                        "El flujo recibido excede el límite de 50 MB.", request.Path);
                }
            }

            // Validación de los 14 pasos en orden estricto (1..13 primero, luego TOFU, luego paso 14 E-DUPLICATE)
            var parsed = V2PacketZipService.ReadPacketZip(
                zipPath,
                enforceStrictSignature: true,
                validateTimestamp: true,
                checkAndRecordReplay: false);

            var manifest = parsed.Manifest;

            if (!string.Equals(manifest.PacketType, expectedPacketType, StringComparison.OrdinalIgnoreCase))
            {
                TryDeleteFile(zipPath);
                return V2ProblemDetails.ToResult("E-ZIP-STRUCTURE", StatusCodes.Status400BadRequest,
                    $"Este endpoint requiere packetType='{expectedPacketType}', recibido '{manifest.PacketType}'.", request.Path);
            }

            // Validación TOFU contra TrustedPeers -> 403 E-CERT-UNTRUSTED si la huella cambió
            var knownPeer = NodeRuntimeState.NetworkPeers.FirstOrDefault(p =>
                p.NodeId.Equals(manifest.SourceNode, StringComparison.OrdinalIgnoreCase));

            if (knownPeer != null)
            {
                V2NetworkClient.ApplyTofuThumbprintCheck(knownPeer, manifest.CertificateThumbprintSha256);
                if (knownPeer.HasThumbprintMismatch || string.Equals(knownPeer.Status, "blocked", StringComparison.OrdinalIgnoreCase))
                {
                    AppDbContext.UpsertTrustedPeer(knownPeer);
                    NodeRuntimeState.NotifyPeerChanged(knownPeer);
                    TryDeleteFile(zipPath);
                    return V2ProblemDetails.ToResult("E-CERT-UNTRUSTED", StatusCodes.Status403Forbidden,
                        $"Huella X.509 de {manifest.SourceNode} no coincide con la huella fijada (TOFU).", request.Path);
                }
            }

            // Paso 14: 409 E-DUPLICATE (SeenPackets en SQLite)
            using (var db = new AppDbContext())
            {
                string normPacketId = manifest.PacketId.Trim().ToLowerInvariant();
                if (db.SeenPackets.Any(sp => sp.PacketId == normPacketId))
                {
                    TryDeleteFile(zipPath);
                    return V2ProblemDetails.ToResult("E-DUPLICATE", StatusCodes.Status409Conflict,
                        $"El packetId '{normPacketId}' ya fue procesado anteriormente (Anti-Replay).", request.Path);
                }

                db.SeenPackets.Add(new SeenPacketEntity
                {
                    PacketId = normPacketId,
                    SourceNode = manifest.SourceNode,
                    PacketTimestampUtc = DateTime.UtcNow,
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

                string receivedIso = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
                return Results.Accepted($"/api/requests/{solicitud.Id}", new
                {
                    packetId = solicitud.PacketId,
                    status = "accepted",
                    receivedAtUtc = receivedIso,
                    requestId = solicitud.Id,
                    packetType = manifest.PacketType,
                    zipFileName = fileName,
                    algorithmCode = solicitud.AlgoritmoCodigo,
                    signatureValid = solicitud.FirmaX509Valida,
                    receiverNode = NodeRuntimeState.CurrentNodeId,
                    timestampUtc = receivedIso
                });
            }
        }
        catch (PacketValidationException pvEx)
        {
            TryDeleteFile(zipPath);
            return V2ProblemDetails.ToResult(pvEx.ErrorCode, pvEx.HttpStatusCode, pvEx.Message, request.Path);
        }
        catch (Exception ex)
        {
            TryDeleteFile(zipPath);
            return V2ProblemDetails.ToResult("E-INTERNAL", StatusCodes.Status400BadRequest, ex.Message, request.Path);
        }
    }

    private static async Task<IResult> HandleCryptoForwardEndpointAsync(HttpRequest request)
    {
        if (!await CryptoConcurrencyGate.WaitAsync(0))
        {
            return V2ProblemDetails.ToResult("E-BUSY", StatusCodes.Status503ServiceUnavailable,
                "Se alcanzó el límite máximo de 10 operaciones criptográficas simultáneas.", request.Path);
        }

        try
        {
            var (rawRequestBytes, signatureBase64, requesterCertPem, payloadBytes, payloadFileName) =
                await ExtractSignedMultipartCryptoRequestAsync(request);

            // Verificar firma RSA-PSS-SHA256 sobre los bytes crudos exactos de la parte 'request' -> 422 E-SIGNATURE
            if (!V2CertificateService.VerifyWithPem(rawRequestBytes, signatureBase64, requesterCertPem))
            {
                return V2ProblemDetails.ToResult("E-SIGNATURE", StatusCodes.Status422UnprocessableEntity,
                    "La firma RSA-PSS-SHA256 de 'requestSignature' sobre los bytes crudos de 'request' es inválida.", request.Path);
            }

            var fwdReq = JsonSerializer.Deserialize<V2CryptoForwardRequest>(rawRequestBytes, JsonOpts)
                ?? throw new PacketValidationException("E-MANIFEST", 400, "No se pudo deserializar la parte 'request'.");

            ValidateCommonCryptoRequestMetadata(
                fwdReq.RequestId,
                fwdReq.RequesterNode,
                fwdReq.TargetNode,
                fwdReq.AlgorithmCode,
                fwdReq.TimestampUtc,
                requesterCertPem,
                checkReplay: true);

            string algCode = fwdReq.AlgorithmCode.Trim().ToUpperInvariant();
            string requesterCertPemCopy = requesterCertPem;

            Func<Task<(V2CryptoForwardResponse? ForwardRes, string? ResultZipPath)>> work = () =>
                Task.FromResult<(V2CryptoForwardResponse?, string?)>((
                    ExecuteForwardCryptoCore(fwdReq, payloadBytes, payloadFileName, requesterCertPemCopy),
                    null));

            if (fwdReq.ForceAsync)
            {
                var job = V2CryptoJobManager.EnqueueJob(fwdReq.RequestId, fwdReq.RequesterNode, "forward", algCode, work);
                return BuildJobAcceptedResult(job);
            }

            var workTask = Task.Run(work);
            var completed = await Task.WhenAny(workTask, Task.Delay(SyncCryptoTimeout));
            if (completed != workTask)
            {
                var job = V2CryptoJobManager.EnqueueJob(fwdReq.RequestId, fwdReq.RequesterNode, "forward", algCode, () => workTask);
                return BuildJobAcceptedResult(job);
            }

            var (forwardResponse, _) = await workTask;
            return Results.Ok(forwardResponse);
        }
        catch (PacketValidationException pve)
        {
            return V2ProblemDetails.ToResult(pve.ErrorCode, pve.HttpStatusCode, pve.Message, request.Path);
        }
        catch (Exception ex)
        {
            return V2ProblemDetails.ToResult("E-INTERNAL", StatusCodes.Status400BadRequest, ex.Message, request.Path);
        }
        finally
        {
            CryptoConcurrencyGate.Release();
        }
    }

    private static async Task<IResult> HandleCryptoInverseEndpointAsync(HttpRequest request)
    {
        if (!await CryptoConcurrencyGate.WaitAsync(0))
        {
            return V2ProblemDetails.ToResult("E-BUSY", StatusCodes.Status503ServiceUnavailable,
                "Se alcanzó el límite máximo de 10 operaciones criptográficas simultáneas.", request.Path);
        }

        try
        {
            var (rawRequestBytes, signatureBase64, requesterCertPem, payloadBytes, _) =
                await ExtractSignedMultipartCryptoRequestAsync(request);

            if (!V2CertificateService.VerifyWithPem(rawRequestBytes, signatureBase64, requesterCertPem))
            {
                return V2ProblemDetails.ToResult("E-SIGNATURE", StatusCodes.Status422UnprocessableEntity,
                    "La firma RSA-PSS-SHA256 de 'requestSignature' sobre los bytes crudos de 'request' es inválida.", request.Path);
            }

            var invReq = JsonSerializer.Deserialize<V2CryptoInverseRequest>(rawRequestBytes, JsonOpts)
                ?? throw new PacketValidationException("E-MANIFEST", 400, "No se pudo deserializar la parte 'request'.");

            ValidateCommonCryptoRequestMetadata(
                invReq.RequestId,
                invReq.RequesterNode,
                invReq.TargetNode,
                invReq.AlgorithmCode,
                invReq.TimestampUtc,
                requesterCertPem,
                checkReplay: true);

            string algCode = invReq.AlgorithmCode.Trim().ToUpperInvariant();
            string requesterCertPemCopy = requesterCertPem;

            Func<Task<(V2CryptoForwardResponse? ForwardRes, string? ResultZipPath)>> work = () =>
                Task.FromResult<(V2CryptoForwardResponse?, string?)>((
                    null,
                    ExecuteInverseCryptoCore(invReq, payloadBytes, requesterCertPemCopy)));

            if (invReq.ForceAsync)
            {
                var job = V2CryptoJobManager.EnqueueJob(invReq.RequestId, invReq.RequesterNode, "inverse", algCode, work);
                return BuildJobAcceptedResult(job);
            }

            var workTask = Task.Run(work);
            var completed = await Task.WhenAny(workTask, Task.Delay(SyncCryptoTimeout));
            if (completed != workTask)
            {
                var job = V2CryptoJobManager.EnqueueJob(invReq.RequestId, invReq.RequesterNode, "inverse", algCode, () => workTask);
                return BuildJobAcceptedResult(job);
            }

            var (_, resultZipPath) = await workTask;
            byte[] zipBytes = await File.ReadAllBytesAsync(resultZipPath!);
            return Results.File(zipBytes, "application/zip", Path.GetFileName(resultZipPath));
        }
        catch (PacketValidationException pve)
        {
            return V2ProblemDetails.ToResult(pve.ErrorCode, pve.HttpStatusCode, pve.Message, request.Path);
        }
        catch (Exception ex)
        {
            return V2ProblemDetails.ToResult("E-INTERNAL", StatusCodes.Status400BadRequest, ex.Message, request.Path);
        }
        finally
        {
            CryptoConcurrencyGate.Release();
        }
    }

    /// <summary>
    /// Sección 13.2: Validaciones obligatorias en /api/crypto/forward e inverse:
    /// - Cert X.509 válido y CN == requesterNode (422 E-CERT)
    /// - TOFU (403 E-CERT-UNTRUSTED)
    /// - targetNode == ownNodeId (400 E-MANIFEST)
    /// - timestampUtc ±10 min (422 E-TIMESTAMP)
    /// - Algoritmo oficial (400 E-ALGORITHM) y provisto por este nodo (404 E-ALGORITHM-NOT-PROVIDED)
    /// - requestId no repetido (409 E-DUPLICATE).
    /// </summary>
    private static void ValidateCommonCryptoRequestMetadata(
        string requestId,
        string requesterNode,
        string? targetNode,
        string algorithmCode,
        string timestampUtc,
        string requesterCertPem,
        bool checkReplay)
    {
        using var requesterCert = V2CertificateService.LoadCertificateFromPemOrBase64(requesterCertPem);
        if (!V2CertificateService.ValidateCertificateMetadata(requesterCert, requesterNode, out string certErr))
            throw new PacketValidationException("E-CERT", 422, certErr);

        var knownPeer = NodeRuntimeState.NetworkPeers.FirstOrDefault(p =>
            p.NodeId.Equals(requesterNode, StringComparison.OrdinalIgnoreCase));
        if (knownPeer != null)
        {
            string reqThumb = V2CertificateService.GetThumbprintSha256Hex(requesterCert);
            V2NetworkClient.ApplyTofuThumbprintCheck(knownPeer, reqThumb);
            if (knownPeer.HasThumbprintMismatch)
                throw new PacketValidationException("E-CERT-UNTRUSTED", 403, $"Cambio de huella TOFU detectado para {requesterNode}.");
        }

        if (!string.IsNullOrWhiteSpace(targetNode) &&
            !string.Equals(targetNode.Trim(), NodeRuntimeState.CurrentNodeId, StringComparison.OrdinalIgnoreCase))
        {
            throw new PacketValidationException(
                "E-MANIFEST",
                400,
                $"La petición está dirigida a targetNode='{targetNode}', pero este nodo es '{NodeRuntimeState.CurrentNodeId}'.");
        }

        if (!V2FormatValidators.IsValidTimestampUtc(timestampUtc) ||
            !DateTime.TryParseExact(
                timestampUtc,
                "yyyy-MM-dd'T'HH:mm:ss'Z'",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal,
                out DateTime reqTimeUtc) ||
            Math.Abs((DateTime.UtcNow - reqTimeUtc).TotalMinutes) > V2PacketZipService.TimestampWindow.TotalMinutes)
        {
            throw new PacketValidationException("E-TIMESTAMP", 422, $"El timestampUtc '{timestampUtc}' es inválido o está fuera de ±10 minutos.");
        }

        string algCode = (algorithmCode ?? "").Trim().ToUpperInvariant();
        if (!CryptoCatalog.IsOfficialCode(algCode))
            throw new PacketValidationException("E-ALGORITHM", 400, $"Algoritmo '{algCode}' desconocido.");

        if (!NodeRuntimeState.OwnedAlgorithms.Contains(algCode, StringComparer.OrdinalIgnoreCase))
        {
            throw new PacketValidationException(
                "E-ALGORITHM-NOT-PROVIDED",
                404,
                $"El algoritmo '{algCode}' no es provisto por {NodeRuntimeState.CurrentNodeId} (dueño oficial: {NodeRuntimeState.GetOwnerNodeForAlgorithm(algCode)}).");
        }

        if (checkReplay && !string.IsNullOrWhiteSpace(requestId))
        {
            using var db = new AppDbContext();
            string normReqId = $"req:{requestId.Trim().ToLowerInvariant()}";
            if (db.SeenPackets.Any(sp => sp.PacketId == normReqId))
            {
                throw new PacketValidationException("E-DUPLICATE", 409, $"El requestId '{requestId}' ya fue procesado anteriormente.");
            }
            db.SeenPackets.Add(new SeenPacketEntity
            {
                PacketId = normReqId,
                SourceNode = requesterNode,
                PacketTimestampUtc = reqTimeUtc,
                ReceivedAtUtc = DateTime.UtcNow
            });
            db.SaveChanges();
        }
    }

    public static V2CryptoForwardResponse ExecuteForwardCryptoCore(
        V2CryptoForwardRequest req,
        byte[] plainPayload,
        string? fileName,
        string requesterCertPem)
    {
        using var requesterCert = V2CertificateService.LoadCertificateFromPemOrBase64(requesterCertPem);
        string packetId = Guid.TryParse(req.PacketId, out Guid g)
            ? g.ToString("D").ToLowerInvariant()
            : Guid.NewGuid().ToString("D").ToLowerInvariant();
        string requestId = string.IsNullOrWhiteSpace(req.RequestId) ? packetId : req.RequestId.Trim().ToLowerInvariant();
        string algCode = req.AlgorithmCode.Trim().ToUpperInvariant();

        string? incomingKeyInput = null;
        if (req.Secrets != null)
        {
            var secretsDict = V2EnvelopeService.OpenSecretsDictionary(req.Secrets, requestId, packetId);
            if (secretsDict.TryGetValue("key", out var kVal))
                incomingKeyInput = kVal;
            else if (secretsDict.Values.FirstOrDefault() is { } firstVal)
                incomingKeyInput = firstVal;
        }

        byte[] cipherBytes;
        byte[] rawKeyBytes;
        var pubParams = new Dictionary<string, string>(StringComparer.Ordinal);

        if (algCode == "AESGCM")
        {
            // Tabla 4.2 AESGCM: keySizeBits ("128" o "256"), nonceBase64 (12 B), tagBase64 (16 B), AAD = Encoding.UTF8.GetBytes(packetId)
            int keyBytesLen = req.KeySizeBits == 128 ? 16 : 32;
            if (!string.IsNullOrWhiteSpace(incomingKeyInput))
            {
                var candidates = SymmetricKeyHelper.BuildCandidateKeys(incomingKeyInput, keyBytesLen, "AESGCM");
                try
                {
                    rawKeyBytes = candidates[0].ToArray();
                    keyBytesLen = rawKeyBytes.Length;
                }
                finally
                {
                    SymmetricKeyHelper.ZeroCandidateKeys(candidates);
                }
            }
            else
            {
                rawKeyBytes = RandomNumberGenerator.GetBytes(keyBytesLen);
            }

            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] tag = new byte[16];
            cipherBytes = new byte[plainPayload.Length];
            byte[] aad = Encoding.UTF8.GetBytes(packetId);

            using (var aes = new AesGcm(rawKeyBytes, 16))
            {
                aes.Encrypt(nonce, plainPayload, cipherBytes, tag, aad);
            }

            pubParams["keySizeBits"] = (keyBytesLen * 8).ToString();
            pubParams["nonceBase64"] = Convert.ToBase64String(nonce);
            pubParams["tagBase64"] = Convert.ToBase64String(tag);
        }
        else if (algCode == "DES")
        {
            // Tabla 4.2 DES: mode="CBC", padding="PKCS7", ivBase64 (8 B), clave de 8 bytes
            using var des = DES.Create();
            des.Mode = CipherMode.CBC;
            des.Padding = PaddingMode.PKCS7;

            if (!string.IsNullOrWhiteSpace(incomingKeyInput))
            {
                var candidates = SymmetricKeyHelper.BuildCandidateKeys(incomingKeyInput, 8, "DES");
                try
                {
                    rawKeyBytes = candidates[0].ToArray();
                    des.Key = rawKeyBytes;
                }
                finally
                {
                    SymmetricKeyHelper.ZeroCandidateKeys(candidates);
                }
            }
            else
            {
                des.GenerateKey();
                rawKeyBytes = des.Key;
            }
            des.GenerateIV();

            cipherBytes = des.EncryptCbc(plainPayload, des.IV, PaddingMode.PKCS7);
            pubParams["mode"] = "CBC";
            pubParams["padding"] = "PKCS7";
            pubParams["ivBase64"] = Convert.ToBase64String(des.IV);
        }
        else
        {
            var strategy = CryptoCatalog.GetStrategy(algCode);
            var res = strategy.Encrypt(plainPayload, incomingKeyInput, packetId);
            cipherBytes = res.OutputBytes;
            rawKeyBytes = Encoding.UTF8.GetBytes(res.SecretKeyBase64);
            foreach (var kv in V2PacketZipService.ParseFlatPublicParameters(res.PublicParametersJson))
                pubParams[kv.Key] = kv.Value;
        }

        try
        {
            string secretKeyBase64 = Convert.ToBase64String(rawKeyBytes);
            string pubJson = JsonSerializer.Serialize(pubParams);
            string officialKeyId = V2FormatValidators.BuildKeyId(NodeRuntimeState.CurrentNodeId, packetId);

            var registro = new RegistroCifrado
            {
                UsuarioId = 0,
                PacketId = packetId,
                NombreArchivo = string.IsNullOrWhiteSpace(fileName) ? req.OriginalFileName : fileName,
                Extension = string.IsNullOrWhiteSpace(req.OriginalExtension) ? ".bin" : req.OriginalExtension,
                BytesCifrados = Convert.ToBase64String(cipherBytes),
                AlgoritmoCodigo = algCode,
                ParametrosPublicosJson = pubJson,
                LlaveSecretaBase64 = secretKeyBase64,
                LinkDescifradoRemoto = officialKeyId,
                NodoRaiz = NodeRuntimeState.CurrentNodeId,
                FirmaRaizBase64 = V2CertificateService.SignDataPss(cipherBytes),
                RutaSaltosJson = JsonSerializer.Serialize(new[] { req.RequesterNode, NodeRuntimeState.CurrentNodeId }),
                Origen = "API-v2.0",
                FechaOperacion = DateTime.Now
            };

            try
            {
                using var db = new AppDbContext();
                if (db.Usuarios.Any())
                {
                    registro.UsuarioId = db.Usuarios.First().Id;
                    db.RegistrosCifrados.Add(registro);
                    db.SaveChanges();
                }
            }
            catch { }

            string zipPath = V2PacketZipService.CreatePacketZip(
                registro,
                cipherBytes,
                packetType: "package",
                operation: "forward",
                requestId: requestId,
                producerNode: NodeRuntimeState.CurrentNodeId,
                explicitPublicParameters: pubParams,
                originalSizeBytesOverride: plainPayload.Length);

            byte[] zipBytes = File.ReadAllBytes(zipPath);

            // Sellar el diccionario {"key": secretKeyBase64} con CC-ENV-1 usando AAD = requestId
            var keyEnvelope = V2EnvelopeService.SealSecretsDictionary(
                new Dictionary<string, string>(StringComparer.Ordinal) { ["key"] = secretKeyBase64 },
                requesterCert,
                req.RequesterNode,
                requestId);

            return new V2CryptoForwardResponse
            {
                RequestId = requestId,
                PacketId = packetId,
                ProducerNode = NodeRuntimeState.CurrentNodeId,
                AlgorithmCode = algCode,
                Operation = "forward",
                CiphertextBase64 = Convert.ToBase64String(cipherBytes),
                EncryptedSha256 = Convert.ToHexString(SHA256.HashData(cipherBytes)).ToLowerInvariant(),
                PublicParameters = pubParams,
                PublicParametersSha256 = PacketManifest.ComputePublicParametersSha256(pubParams),
                KeyRef = new ManifestKeyRef
                {
                    KeyId = officialKeyId,
                    OwnerNode = NodeRuntimeState.CurrentNodeId
                },
                SecretKeyEnvelope = keyEnvelope,
                PackageZipBase64 = Convert.ToBase64String(zipBytes),
                TimestampUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rawKeyBytes);
        }
    }

    public static string ExecuteInverseCryptoCore(
        V2CryptoInverseRequest req,
        byte[] cipherOrPackageBytes,
        string requesterCertPem)
    {
        using var requesterCert = V2CertificateService.LoadCertificateFromPemOrBase64(requesterCertPem);
        string algCode = req.AlgorithmCode.Trim().ToUpperInvariant();
        string packetId = string.IsNullOrWhiteSpace(req.PacketId)
            ? Guid.NewGuid().ToString("D").ToLowerInvariant()
            : req.PacketId.Trim().ToLowerInvariant();
        string requestId = string.IsNullOrWhiteSpace(req.RequestId) ? packetId : req.RequestId.Trim().ToLowerInvariant();

        byte[] cipherBytes = cipherOrPackageBytes;
        var pubParams = new Dictionary<string, string>(req.PublicParameters, StringComparer.Ordinal);
        string origFileName = "resultado.bin";
        string origExtension = ".bin";

        // Si el cliente adjuntó un paquete .zip completo en 'package', validarlo con los pasos 1..13 de la Sección 13.1
        if (cipherOrPackageBytes.Length >= 4 &&
            cipherOrPackageBytes[0] == 0x50 && cipherOrPackageBytes[1] == 0x4B &&
            cipherOrPackageBytes[2] == 0x03 && cipherOrPackageBytes[3] == 0x04)
        {
            string tempInZip = Path.Combine(Path.GetTempPath(), $"v2_inv_in_{Guid.NewGuid():N}.zip");
            try
            {
                File.WriteAllBytes(tempInZip, cipherOrPackageBytes);
                var parsedPkg = V2PacketZipService.ReadPacketZip(
                    tempInZip,
                    enforceStrictSignature: true,
                    validateTimestamp: true,
                    checkAndRecordReplay: false);
                cipherBytes = parsedPkg.PayloadBytes;
                packetId = parsedPkg.Manifest.PacketId;
                origFileName = parsedPkg.Manifest.OriginalFileName;
                origExtension = parsedPkg.Manifest.OriginalExtension;
                foreach (var kv in parsedPkg.Manifest.PublicParameters)
                    pubParams[kv.Key] = kv.Value;
            }
            finally
            {
                TryDeleteFile(tempInZip);
            }
        }

        string? secretKeyInput = null;
        if (req.Secrets != null)
        {
            var secretsDict = V2EnvelopeService.OpenSecretsDictionary(req.Secrets, requestId, packetId);
            if (secretsDict.TryGetValue("key", out var kVal))
                secretKeyInput = kVal;
            else if (secretsDict.Values.FirstOrDefault() is { } firstVal)
                secretKeyInput = firstVal;
        }
        else
        {
            string lookupId = !string.IsNullOrWhiteSpace(req.KeyId) ? req.KeyId : packetId;
            using var db = new AppDbContext();
            var stored = db.RegistrosCifrados.FirstOrDefault(r =>
                r.PacketId == lookupId ||
                r.LinkDescifradoRemoto == lookupId ||
                r.PacketId == packetId);
            if (stored != null && !string.IsNullOrWhiteSpace(stored.LlaveSecretaBase64))
            {
                secretKeyInput = stored.LlaveSecretaBase64;
            }
        }

        if (string.IsNullOrWhiteSpace(secretKeyInput))
            throw new PacketValidationException("E-ENV-DECRYPT", 401, "No se proporcionó sobre 'secrets' CC-ENV-1 ni se encontró keyId local.");

        byte[] plainBytes;
        try
        {
            var strategy = CryptoCatalog.GetStrategy(algCode);
            var ctx = new DecryptionContext(
                PacketId: packetId,
                RequestId: requestId,
                OriginalFileName: origFileName,
                OriginalExtension: origExtension);
            var dec = strategy.Decrypt(cipherBytes, secretKeyInput, JsonSerializer.Serialize(pubParams), ctx);
            plainBytes = dec.OutputBytes;
        }
        catch (Exception ex)
        {
            throw new PacketValidationException("E-ENV-DECRYPT", 401, $"Fallo en el descifrado criptográfico ({algCode}): {ex.Message}");
        }

        try
        {
            // Sellar el resultado en claro para un paquete 'result' v2.0:
            // - AAD = Encoding.UTF8.GetBytes(resultPacketId)
            // - resultado.enc recibe exclusivamente los bytes cifrados (resultadoEncBytes)
            // - manifest.resultEnvelope recibe el sobre CC-ENV-1 SIN ciphertextBase64
            string resultPacketId = Guid.NewGuid().ToString("D").ToLowerInvariant();
            var resultEnvelopeForManifest = V2EnvelopeService.SealDetached(
                plainBytes,
                requesterCert,
                req.RequesterNode,
                aadContext: resultPacketId,
                out byte[] resultadoEncBytes);

            var resultRec = new RegistroCifrado
            {
                PacketId = resultPacketId,
                AlgoritmoCodigo = algCode,
                NombreArchivo = origFileName,
                Extension = origExtension,
                NodoRaiz = NodeRuntimeState.CurrentNodeId,
                LinkDescifradoRemoto = V2FormatValidators.BuildKeyId(NodeRuntimeState.CurrentNodeId, resultPacketId),
                ParametrosPublicosJson = JsonSerializer.Serialize(pubParams)
            };

            return V2PacketZipService.CreatePacketZip(
                resultRec,
                resultadoEncBytes,
                packetType: "result",
                operation: "inverse",
                requestId: requestId,
                producerNode: NodeRuntimeState.CurrentNodeId,
                explicitPublicParameters: pubParams,
                resultEnvelope: resultEnvelopeForManifest,
                originalSizeBytesOverride: plainBytes.Length);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plainBytes);
        }
    }

    private static async Task<(byte[] RawRequestBytes, string RequestSignatureBase64, string RequesterCertPem, byte[] PayloadBytes, string? PayloadFileName)>
        ExtractSignedMultipartCryptoRequestAsync(HttpRequest request)
    {
        if (!request.HasFormContentType)
            throw new PacketValidationException("E-MANIFEST", 400, "Se requiere contenido multipart/form-data.");

        var form = await request.ReadFormAsync();

        // 1. 'request' (preservar bytes crudos UTF-8 exactos sin re-serializar)
        byte[] rawRequestBytes;
        var reqFile = form.Files.GetFile("request");
        if (reqFile != null)
        {
            using var ms = new MemoryStream();
            await reqFile.CopyToAsync(ms);
            rawRequestBytes = ms.ToArray();
        }
        else if (form.TryGetValue("request", out var reqVal) && !string.IsNullOrWhiteSpace(reqVal))
        {
            rawRequestBytes = Encoding.UTF8.GetBytes(reqVal.ToString());
        }
        else
        {
            throw new PacketValidationException("E-MANIFEST", 400, "Falta la parte obligatoria 'request' en multipart/form-data.");
        }

        // 2. 'requestSignature'
        string signatureBase64 = string.Empty;
        if (form.TryGetValue("requestSignature", out var sigVal))
            signatureBase64 = sigVal.ToString().Trim();
        else if (form.Files.GetFile("requestSignature") is { } sigFile)
        {
            using var sr = new StreamReader(sigFile.OpenReadStream(), Encoding.UTF8);
            signatureBase64 = (await sr.ReadToEndAsync()).Trim();
        }

        if (string.IsNullOrWhiteSpace(signatureBase64))
            throw new PacketValidationException("E-SIGNATURE", 422, "Falta la parte obligatoria 'requestSignature'.");

        // 3. 'requesterCertificate'
        string requesterCertPem = string.Empty;
        if (form.TryGetValue("requesterCertificate", out var certVal))
            requesterCertPem = certVal.ToString().Trim();
        else if (form.Files.GetFile("requesterCertificate") is { } certFile)
        {
            using var sr = new StreamReader(certFile.OpenReadStream(), Encoding.UTF8);
            requesterCertPem = (await sr.ReadToEndAsync()).Trim();
        }

        if (string.IsNullOrWhiteSpace(requesterCertPem))
            throw new PacketValidationException("E-CERT", 422, "Falta la parte obligatoria 'requesterCertificate'.");

        // 4. 'payload' | 'cover' | 'package'
        byte[] payloadBytes = Array.Empty<byte>();
        string? payloadFileName = null;
        var payloadFile = form.Files.GetFile("payload")
                          ?? form.Files.GetFile("package")
                          ?? form.Files.GetFile("cover");

        if (payloadFile != null)
        {
            if (payloadFile.Length > MaxRequestSizeBytes)
                throw new PacketValidationException("E-SIZE", 413, "El payload adjunto supera el límite de 50 MB.");

            payloadFileName = payloadFile.FileName;
            using var ms = new MemoryStream();
            await payloadFile.CopyToAsync(ms);
            payloadBytes = ms.ToArray();
        }
        else if (form.TryGetValue("payload", out var payVal))
        {
            payloadBytes = Encoding.UTF8.GetBytes(payVal.ToString());
        }

        return (rawRequestBytes, signatureBase64, requesterCertPem, payloadBytes, payloadFileName);
    }

    private static IResult BuildJobAcceptedResult(V2CryptoJobRecord job)
    {
        return Results.Accepted($"/api/jobs/{job.JobId}", new V2JobAcceptedResponse
        {
            JobId = job.JobId,
            RequestId = job.RequestId,
            Status = job.Status,
            StatusUrl = $"/api/jobs/{job.JobId}",
            ResultUrl = $"/api/jobs/{job.JobId}/result",
            RetryAfterSeconds = 5,
            TimestampUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        });
    }

    private static IResult HandleGetJobStatus(string jobId, HttpRequest request)
    {
        var job = V2CryptoJobManager.GetJob(jobId);
        if (job == null)
            return V2ProblemDetails.ToResult("E-NOT-FOUND", StatusCodes.Status404NotFound, $"El trabajo '{jobId}' no existe o expiró.", request.Path);

        string callerNode = request.Headers["X-CC-Node"].ToString().Trim();
        if (!string.IsNullOrWhiteSpace(job.RequesterNode) &&
            !string.Equals(callerNode, job.RequesterNode, StringComparison.OrdinalIgnoreCase))
        {
            return V2ProblemDetails.ToResult("E-FORBIDDEN", StatusCodes.Status403Forbidden,
                $"La cabecera X-CC-Node ('{callerNode}') no coincide con el propietario del job ('{job.RequesterNode}').", request.Path);
        }

        return Results.Ok(new V2JobStatusResponse
        {
            JobId = job.JobId,
            RequestId = job.RequestId,
            RequesterNode = job.RequesterNode,
            Operation = job.Operation,
            AlgorithmCode = job.AlgorithmCode,
            Status = job.Status,
            ResultUrl = job.Status == "completed" ? $"/api/jobs/{job.JobId}/result" : null,
            ErrorCode = job.ErrorCode,
            ErrorDetail = job.ErrorDetail,
            CreatedAtUtc = job.CreatedAtUtc.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            CompletedAtUtc = job.CompletedAtUtc?.ToString("yyyy-MM-ddTHH:mm:ssZ")
        });
    }

    private static IResult HandleGetJobResult(string jobId, HttpRequest request)
    {
        var job = V2CryptoJobManager.GetJob(jobId);
        if (job == null)
            return V2ProblemDetails.ToResult("E-NOT-FOUND", StatusCodes.Status404NotFound, $"El trabajo '{jobId}' no existe o expiró.", request.Path);

        string callerNode = request.Headers["X-CC-Node"].ToString().Trim();
        if (!string.IsNullOrWhiteSpace(job.RequesterNode) &&
            !string.Equals(callerNode, job.RequesterNode, StringComparison.OrdinalIgnoreCase))
        {
            return V2ProblemDetails.ToResult("E-FORBIDDEN", StatusCodes.Status403Forbidden,
                $"La cabecera X-CC-Node ('{callerNode}') no coincide con el propietario del job ('{job.RequesterNode}').", request.Path);
        }

        if (job.Status == "running")
            return BuildJobAcceptedResult(job);

        if (job.Status == "failed")
            return V2ProblemDetails.ToResult(job.ErrorCode ?? "E-INTERNAL", StatusCodes.Status400BadRequest, job.ErrorDetail ?? "Job falló.", request.Path);

        if (!string.IsNullOrWhiteSpace(job.ResultFilePath) && File.Exists(job.ResultFilePath))
        {
            byte[] zipBytes = File.ReadAllBytes(job.ResultFilePath);
            return Results.File(zipBytes, "application/zip", Path.GetFileName(job.ResultFilePath));
        }

        if (job.ForwardResult != null)
            return Results.Ok(job.ForwardResult);

        return V2ProblemDetails.ToResult("E-NOT-FOUND", StatusCodes.Status404NotFound, "Resultado no disponible.", request.Path);
    }

    public static AsymmetricKeyEntity GetOrCreateAsymmetricKey(string keyId, string algorithmCode = "RSA")
    {
        using var db = new AppDbContext();
        var existing = db.AsymmetricKeys.FirstOrDefault(k => k.KeyId == keyId);
        if (existing != null)
            return existing;

        using var rsa = RSA.Create(2048);
        string pubPem = rsa.ExportRSAPublicKeyPem();
        byte[] privBytes = rsa.ExportPkcs8PrivateKey();
        try
        {
            byte[] protectedPriv = ProtectedData.Protect(privBytes, AsymmetricDpapiEntropy, DataProtectionScope.CurrentUser);
            var entity = new AsymmetricKeyEntity
            {
                KeyId = keyId,
                AlgorithmCode = algorithmCode,
                OwnerNode = NodeRuntimeState.CurrentNodeId,
                PublicKeyPem = pubPem,
                ProtectedPrivateKeyBase64 = Convert.ToBase64String(protectedPriv),
                ParametersJson = "{\"keySizeBits\":\"2048\"}",
                CreatedAtUtc = DateTime.UtcNow
            };
            db.AsymmetricKeys.Add(entity);
            db.SaveChanges();
            return entity;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privBytes);
        }
    }

    private static IResult HandleGetAsymmetricPublicKey(string keyId)
    {
        if (string.IsNullOrWhiteSpace(keyId))
            return V2ProblemDetails.ToResult("E-NOT-FOUND", StatusCodes.Status404NotFound, "Se requiere keyId.", "/api/keys");

        using var db = new AppDbContext();
        var key = db.AsymmetricKeys.FirstOrDefault(k => k.KeyId == keyId);
        if (key == null)
        {
            if (string.Equals(keyId, "default", StringComparison.OrdinalIgnoreCase) ||
                V2FormatValidators.IsValidKeyId(keyId))
            {
                key = GetOrCreateAsymmetricKey(keyId, "RSA");
            }
            else
            {
                return V2ProblemDetails.ToResult("E-NOT-FOUND", StatusCodes.Status404NotFound,
                    $"No se encontró la llave pública con keyId='{keyId}' en {NodeRuntimeState.CurrentNodeId}.", $"/api/keys/{keyId}");
            }
        }

        return Results.Ok(new V2PublicKeyResponseDto
        {
            KeyId = key.KeyId,
            AlgorithmCode = key.AlgorithmCode,
            OwnerNode = key.OwnerNode,
            PublicKeyPem = key.PublicKeyPem,
            Parameters = V2PacketZipService.ParseFlatPublicParameters(key.ParametersJson),
            CreatedAtUtc = key.CreatedAtUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
        });
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
            _app = null;
        }
        _cts?.Dispose();
        _cts = null;
        NodeRuntimeState.ApiOnline = false;
    }
}
