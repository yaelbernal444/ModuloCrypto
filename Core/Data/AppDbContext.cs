using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using System.Data;
using System.Security.Cryptography;
using System.Text;

namespace ModuloCrypto.Core.Data;

public class AppDbContext : DbContext
{
    public static string AppDataDirectory { get; } = InitializeAppDataDirectory();

    public static string IncomingPacketsDirectory => EnsureSubDirectory("IncomingPackets");

    public static string OutgoingPacketsDirectory => EnsureSubDirectory("OutgoingPackets");

    public static string DuplicatesBackupDirectory => EnsureSubDirectory("DuplicatesBackup");

    public static string DatabasePath { get; } = ConsolidateAndResolveProductionDatabasePath();

    /// <summary>
    /// Resumen del resultado de la auto-consolidación de bases de datos antiguas en AppContext.BaseDirectory.
    /// </summary>
    public static string LastConsolidationReport { get; private set; } = "Base de datos única lista.";

    private readonly string _connectionDbPath;

    public AppDbContext()
    {
        _connectionDbPath = DatabasePath;
    }

    public AppDbContext(string customDatabasePath)
    {
        _connectionDbPath = string.IsNullOrWhiteSpace(customDatabasePath) ? DatabasePath : customDatabasePath;
    }

    public DbSet<Usuario> Usuarios => Set<Usuario>();
    public DbSet<RegistroCifrado> RegistrosCifrados => Set<RegistroCifrado>();
    public DbSet<SolicitudEntrante> SolicitudesEntrantes => Set<SolicitudEntrante>();
    public DbSet<PeerNode> TrustedPeers => Set<PeerNode>();
    public DbSet<SeenPacketEntity> SeenPackets => Set<SeenPacketEntity>();
    public DbSet<AsymmetricKeyEntity> AsymmetricKeys => Set<AsymmetricKeyEntity>();

    private static string InitializeAppDataDirectory()
    {
        string dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ModuloCrypto");
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static string EnsureSubDirectory(string subFolderName)
    {
        string dir = Path.Combine(AppDataDirectory, subFolderName);
        Directory.CreateDirectory(dir);
        return dir;
    }

    /// <summary>
    /// Auto-consolidación inteligente antes de abrir EF Core:
    /// - Fija DatabasePath = %LOCALAPPDATA%\ModuloCrypto\ModuloCrypto.db.
    /// - Si detecta un ModuloCrypto.db antiguo en AppContext.BaseDirectory (bin\):
    ///   * Si DatabasePath no existe aún, mueve ModuloCrypto.db (y sus -wal/-shm) a DatabasePath.
    ///   * Si DatabasePath ya existe, respalda el duplicado de bin\ en AppDataDirectory\DuplicatesBackup\ y lo elimina de bin\.
    /// - También migra certificados (.pfx/.key) e IncomingPackets/OutgoingPackets desde bin\ hacia AppDataDirectory.
    /// </summary>
    public static string ConsolidateAndResolveProductionDatabasePath()
    {
        Directory.CreateDirectory(AppDataDirectory);
        string targetDbPath = Path.Combine(AppDataDirectory, "ModuloCrypto.db");
        string baseDir = Path.GetFullPath(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        string appDataFull = Path.GetFullPath(AppDataDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

        if (string.Equals(baseDir, appDataFull, StringComparison.OrdinalIgnoreCase))
            return targetDbPath;

        try
        {
            MigrateSupportingArtifactsFromBaseDirectory(baseDir);

            string legacyBinDb = Path.Combine(baseDir, "ModuloCrypto.db");
            if (File.Exists(legacyBinDb))
            {
                SqliteConnection.ClearAllPools();

                if (!File.Exists(targetDbPath))
                {
                    // Realizar checkpoint sobre la BD antigua antes de moverla para integrar su -wal
                    TryCheckpointSingleFile(legacyBinDb);

                    File.Move(legacyBinDb, targetDbPath, overwrite: true);
                    MoveCompanionWalShmIfPresent(legacyBinDb, targetDbPath);
                    BackupLegacyBakFilesInBin(baseDir);

                    LastConsolidationReport = $"BD migrada desde '{legacyBinDb}' hacia '{targetDbPath}'.";
                }
                else
                {
                    string backupDir = DuplicatesBackupDirectory;
                    string stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                    string backupDbPath = Path.Combine(backupDir, $"ModuloCrypto_bin_dup_{stamp}.db");

                    TryCheckpointSingleFile(legacyBinDb);

                    File.Move(legacyBinDb, backupDbPath, overwrite: true);
                    MoveCompanionWalShmIfPresent(legacyBinDb, backupDbPath);
                    BackupLegacyBakFilesInBin(baseDir);

                    LastConsolidationReport = $"Duplicado en bin\\ respaldado en '{backupDbPath}' y eliminado de bin\\.";
                }
            }
            else
            {
                BackupLegacyBakFilesInBin(baseDir);
            }
        }
        catch (Exception ex)
        {
            LastConsolidationReport = $"Aviso en auto-consolidación: {ex.Message}";
        }

        return targetDbPath;
    }

    private static void MigrateSupportingArtifactsFromBaseDirectory(string baseDir)
    {
        try
        {
            foreach (string pattern in new[] { "node_identity_*.pfx", "node_identity_*.key" })
            {
                foreach (string srcFile in Directory.GetFiles(baseDir, pattern, SearchOption.TopDirectoryOnly))
                {
                    string destFile = Path.Combine(AppDataDirectory, Path.GetFileName(srcFile));
                    if (!File.Exists(destFile))
                        File.Move(srcFile, destFile);
                }
            }

            foreach (string folderName in new[] { "IncomingPackets", "OutgoingPackets" })
            {
                string legacyFolder = Path.Combine(baseDir, folderName);
                if (!Directory.Exists(legacyFolder)) continue;

                string targetFolder = Path.Combine(AppDataDirectory, folderName);
                Directory.CreateDirectory(targetFolder);

                foreach (string srcZip in Directory.GetFiles(legacyFolder, "*", SearchOption.TopDirectoryOnly))
                {
                    string destZip = Path.Combine(targetFolder, Path.GetFileName(srcZip));
                    if (!File.Exists(destZip))
                        File.Move(srcZip, destZip);
                }
            }
        }
        catch { }
    }

    private static void TryCheckpointSingleFile(string dbFilePath)
    {
        try
        {
            using var conn = new SqliteConnection(BuildSqliteConnectionString(dbFilePath));
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
            cmd.ExecuteNonQuery();
            conn.Close();
            SqliteConnection.ClearPool(conn);
        }
        catch { }
    }

    private static void MoveCompanionWalShmIfPresent(string sourceDbPath, string destDbPath)
    {
        foreach (string suffix in new[] { "-wal", "-shm" })
        {
            string src = sourceDbPath + suffix;
            string dst = destDbPath + suffix;
            try
            {
                if (File.Exists(src))
                {
                    if (!File.Exists(dst))
                        File.Move(src, dst, overwrite: true);
                    else
                        File.Delete(src);
                }
            }
            catch { }
        }
    }

    private static void BackupLegacyBakFilesInBin(string baseDir)
    {
        try
        {
            foreach (string bakFile in Directory.GetFiles(baseDir, "ModuloCrypto.db.bak.*", SearchOption.TopDirectoryOnly))
            {
                string dest = Path.Combine(DuplicatesBackupDirectory, Path.GetFileName(bakFile));
                File.Move(bakFile, dest, overwrite: true);
            }
        }
        catch { }
    }

    public static string BuildSqliteConnectionString(string dbPath)
    {
        string fullPath = Path.GetFullPath(dbPath);
        string? dir = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(dir))
            Directory.CreateDirectory(dir);

        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = fullPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            DefaultTimeout = 10
        };
        return builder.ToString();
    }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (!optionsBuilder.IsConfigured)
        {
            optionsBuilder.UseSqlite(BuildSqliteConnectionString(_connectionDbPath));
        }
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<Usuario>(entity =>
        {
            entity.ToTable("Usuarios");
            entity.HasIndex(u => u.NombreUsuario).IsUnique();
        });

        modelBuilder.Entity<RegistroCifrado>(entity =>
        {
            entity.ToTable("RegistrosCifrados");
            entity.HasIndex(r => r.PacketId);
            entity.HasOne(r => r.Usuario)
                  .WithMany(u => u.RegistrosCifrados)
                  .HasForeignKey(r => r.UsuarioId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<SolicitudEntrante>(entity =>
        {
            entity.ToTable("SolicitudesEntrantes");
            entity.HasIndex(s => s.PacketId);
            entity.HasIndex(s => s.Estado);
        });

        modelBuilder.Entity<PeerNode>(entity =>
        {
            entity.ToTable("TrustedPeers");
            entity.HasIndex(p => p.NodeId).IsUnique();
        });

        modelBuilder.Entity<SeenPacketEntity>(entity =>
        {
            entity.ToTable("SeenPackets");
            entity.HasIndex(p => p.PacketId).IsUnique();
        });

        modelBuilder.Entity<AsymmetricKeyEntity>(entity =>
        {
            entity.ToTable("AsymmetricKeys");
            entity.HasIndex(k => k.KeyId).IsUnique();
        });
    }

    /// <summary>
    /// Inicializa y migra idempotentemente el esquema SQLite (con PRAGMAs WAL, verificación de todas las tablas y columnas
    /// y recuperación automática con respaldo .bak si la base de datos previa estuviera corrupta).
    /// </summary>
    public static void InitializeDatabase(string? customDatabasePath = null)
    {
        if (customDatabasePath == null)
        {
            ConsolidateAndResolveProductionDatabasePath();
        }

        string targetPath = string.IsNullOrWhiteSpace(customDatabasePath) ? DatabasePath : customDatabasePath;

        try
        {
            ApplySchemaAndMigrations(targetPath);
        }
        catch
        {
            BackupAndRecreateCorruptDatabase(targetPath);
            ApplySchemaAndMigrations(targetPath);
        }

        if (customDatabasePath == null)
        {
            bool ok = TestConnection(out string diag, targetPath);
            NodeRuntimeState.SqliteConnected = ok;
            NodeRuntimeState.SqliteDiagnostic = diag;
        }
    }

    private static void ApplySchemaAndMigrations(string targetPath)
    {
        using var db = new AppDbContext(targetPath);

        // 1. EnsureCreated inicial (crea el archivo si no existe)
        db.Database.EnsureCreated();

        // 2. Activar PRAGMAs de estabilidad y concurrencia
        db.Database.ExecuteSqlRaw("PRAGMA journal_mode = WAL;");
        db.Database.ExecuteSqlRaw("PRAGMA busy_timeout = 5000;");
        db.Database.ExecuteSqlRaw("PRAGMA foreign_keys = ON;");

        // 3. CREATE TABLE IF NOT EXISTS para todas las 6 tablas del contexto
        db.Database.ExecuteSqlRaw(@"
            CREATE TABLE IF NOT EXISTS Usuarios (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                NombreCompleto TEXT NOT NULL DEFAULT '',
                NombreUsuario TEXT NOT NULL UNIQUE,
                PasswordHash TEXT NOT NULL DEFAULT '',
                NodoAsignado TEXT NOT NULL DEFAULT 'EQ01',
                Rol TEXT NOT NULL DEFAULT 'Operador EQ01',
                FechaRegistro TEXT NOT NULL DEFAULT '2026-01-01 00:00:00'
            );");

        db.Database.ExecuteSqlRaw(@"
            CREATE TABLE IF NOT EXISTS RegistrosCifrados (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                UsuarioId INTEGER NOT NULL DEFAULT 0,
                PacketId TEXT NOT NULL DEFAULT '',
                NombreArchivo TEXT NOT NULL DEFAULT '',
                Extension TEXT NOT NULL DEFAULT '.txt',
                BytesCifrados TEXT NOT NULL DEFAULT '',
                AlgoritmoCodigo TEXT NOT NULL DEFAULT 'AESGCM',
                ParametrosPublicosJson TEXT NOT NULL DEFAULT '{{}}',
                LlaveSecretaBase64 TEXT NOT NULL DEFAULT '',
                LinkDescifradoRemoto TEXT NOT NULL DEFAULT '',
                NodoRaiz TEXT NOT NULL DEFAULT 'EQ01',
                FirmaRaizBase64 TEXT NOT NULL DEFAULT '',
                RutaSaltosJson TEXT NOT NULL DEFAULT '[""EQ01""]',
                Origen TEXT NOT NULL DEFAULT 'Local',
                FechaOperacion TEXT NOT NULL DEFAULT '2026-01-01 00:00:00'
            );");

        db.Database.ExecuteSqlRaw(@"
            CREATE TABLE IF NOT EXISTS SolicitudesEntrantes (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                PacketId TEXT NOT NULL DEFAULT '',
                NodoOrigen TEXT NOT NULL DEFAULT '',
                IpOrigen TEXT NOT NULL DEFAULT '',
                NombreZip TEXT NOT NULL DEFAULT '',
                AlgoritmoCodigo TEXT NOT NULL DEFAULT '',
                FirmaX509Valida INTEGER NOT NULL DEFAULT 0,
                RutaZipTemporal TEXT NOT NULL DEFAULT '',
                Estado TEXT NOT NULL DEFAULT 'Pendiente',
                FechaRecepcion TEXT NOT NULL DEFAULT '2026-01-01 00:00:00'
            );");

        db.Database.ExecuteSqlRaw(@"
            CREATE TABLE IF NOT EXISTS TrustedPeers (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                NodeId TEXT NOT NULL UNIQUE,
                TeamNumber INTEGER NOT NULL DEFAULT 0,
                IpAddress TEXT NOT NULL DEFAULT '127.0.0.1',
                Port INTEGER NOT NULL DEFAULT 5001,
                HttpsPort INTEGER NULL,
                RoleLabel TEXT NOT NULL DEFAULT '',
                ProtocolType TEXT NOT NULL DEFAULT 'v2.0',
                Source TEXT NOT NULL DEFAULT 'manual',
                Status TEXT NOT NULL DEFAULT 'offline',
                LastLatency TEXT NOT NULL DEFAULT '--',
                CertThumbprint TEXT NOT NULL DEFAULT '',
                PinnedThumbprintSha256 TEXT NOT NULL DEFAULT '',
                CertificatePem TEXT NOT NULL DEFAULT '',
                AlgorithmsJson TEXT NOT NULL DEFAULT '[]',
                IsConfirmed INTEGER NOT NULL DEFAULT 0,
                HasThumbprintMismatch INTEGER NOT NULL DEFAULT 0,
                LastSeenUtc TEXT NOT NULL DEFAULT '2026-01-01 00:00:00'
            );");

        db.Database.ExecuteSqlRaw(@"
            CREATE TABLE IF NOT EXISTS SeenPackets (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                PacketId TEXT NOT NULL UNIQUE,
                SourceNode TEXT NOT NULL DEFAULT '',
                PacketTimestampUtc TEXT NOT NULL DEFAULT '2026-01-01 00:00:00',
                ReceivedAtUtc TEXT NOT NULL DEFAULT '2026-01-01 00:00:00'
            );");

        db.Database.ExecuteSqlRaw(@"
            CREATE TABLE IF NOT EXISTS AsymmetricKeys (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                KeyId TEXT NOT NULL UNIQUE,
                AlgorithmCode TEXT NOT NULL DEFAULT 'RSA',
                OwnerNode TEXT NOT NULL DEFAULT 'EQ01',
                PublicKeyPem TEXT NOT NULL DEFAULT '',
                ProtectedPrivateKeyBase64 TEXT NOT NULL DEFAULT '',
                ParametersJson TEXT NOT NULL DEFAULT '{{}}',
                CreatedAtUtc TEXT NOT NULL DEFAULT '2026-01-01 00:00:00'
            );");

        // 4. Asegurar todas las columnas de cada tabla consultando PRAGMA table_info("<table>")
        EnsureColumnExists(db, "Usuarios", "NombreCompleto", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "Usuarios", "NombreUsuario", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "Usuarios", "PasswordHash", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "Usuarios", "NodoAsignado", "TEXT NOT NULL DEFAULT 'EQ01'");
        EnsureColumnExists(db, "Usuarios", "Rol", "TEXT NOT NULL DEFAULT 'Operador EQ01'");
        EnsureColumnExists(db, "Usuarios", "FechaRegistro", "TEXT NOT NULL DEFAULT '2026-01-01 00:00:00'");

        EnsureColumnExists(db, "RegistrosCifrados", "UsuarioId", "INTEGER NOT NULL DEFAULT 0");
        EnsureColumnExists(db, "RegistrosCifrados", "PacketId", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "RegistrosCifrados", "NombreArchivo", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "RegistrosCifrados", "Extension", "TEXT NOT NULL DEFAULT '.txt'");
        EnsureColumnExists(db, "RegistrosCifrados", "BytesCifrados", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "RegistrosCifrados", "AlgoritmoCodigo", "TEXT NOT NULL DEFAULT 'AESGCM'");
        EnsureColumnExists(db, "RegistrosCifrados", "ParametrosPublicosJson", "TEXT NOT NULL DEFAULT '{}'");
        EnsureColumnExists(db, "RegistrosCifrados", "LlaveSecretaBase64", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "RegistrosCifrados", "LinkDescifradoRemoto", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "RegistrosCifrados", "NodoRaiz", "TEXT NOT NULL DEFAULT 'EQ01'");
        EnsureColumnExists(db, "RegistrosCifrados", "FirmaRaizBase64", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "RegistrosCifrados", "RutaSaltosJson", "TEXT NOT NULL DEFAULT '[\"EQ01\"]'");
        EnsureColumnExists(db, "RegistrosCifrados", "Origen", "TEXT NOT NULL DEFAULT 'Local'");
        EnsureColumnExists(db, "RegistrosCifrados", "FechaOperacion", "TEXT NOT NULL DEFAULT '2026-01-01 00:00:00'");

        EnsureColumnExists(db, "SolicitudesEntrantes", "PacketId", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "SolicitudesEntrantes", "NodoOrigen", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "SolicitudesEntrantes", "IpOrigen", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "SolicitudesEntrantes", "NombreZip", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "SolicitudesEntrantes", "AlgoritmoCodigo", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "SolicitudesEntrantes", "FirmaX509Valida", "INTEGER NOT NULL DEFAULT 0");
        EnsureColumnExists(db, "SolicitudesEntrantes", "RutaZipTemporal", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "SolicitudesEntrantes", "Estado", "TEXT NOT NULL DEFAULT 'Pendiente'");
        EnsureColumnExists(db, "SolicitudesEntrantes", "FechaRecepcion", "TEXT NOT NULL DEFAULT '2026-01-01 00:00:00'");

        EnsureColumnExists(db, "TrustedPeers", "NodeId", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "TrustedPeers", "TeamNumber", "INTEGER NOT NULL DEFAULT 0");
        EnsureColumnExists(db, "TrustedPeers", "IpAddress", "TEXT NOT NULL DEFAULT '127.0.0.1'");
        EnsureColumnExists(db, "TrustedPeers", "Port", "INTEGER NOT NULL DEFAULT 5001");
        EnsureColumnExists(db, "TrustedPeers", "HttpsPort", "INTEGER NULL");
        EnsureColumnExists(db, "TrustedPeers", "RoleLabel", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "TrustedPeers", "ProtocolType", "TEXT NOT NULL DEFAULT 'v2.0'");
        EnsureColumnExists(db, "TrustedPeers", "Source", "TEXT NOT NULL DEFAULT 'manual'");
        EnsureColumnExists(db, "TrustedPeers", "Status", "TEXT NOT NULL DEFAULT 'offline'");
        EnsureColumnExists(db, "TrustedPeers", "LastLatency", "TEXT NOT NULL DEFAULT '--'");
        EnsureColumnExists(db, "TrustedPeers", "CertThumbprint", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "TrustedPeers", "PinnedThumbprintSha256", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "TrustedPeers", "CertificatePem", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "TrustedPeers", "AlgorithmsJson", "TEXT NOT NULL DEFAULT '[]'");
        EnsureColumnExists(db, "TrustedPeers", "IsConfirmed", "INTEGER NOT NULL DEFAULT 0");
        EnsureColumnExists(db, "TrustedPeers", "HasThumbprintMismatch", "INTEGER NOT NULL DEFAULT 0");
        EnsureColumnExists(db, "TrustedPeers", "LastSeenUtc", "TEXT NOT NULL DEFAULT '2026-01-01 00:00:00'");

        EnsureColumnExists(db, "SeenPackets", "PacketId", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "SeenPackets", "SourceNode", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "SeenPackets", "PacketTimestampUtc", "TEXT NOT NULL DEFAULT '2026-01-01 00:00:00'");
        EnsureColumnExists(db, "SeenPackets", "ReceivedAtUtc", "TEXT NOT NULL DEFAULT '2026-01-01 00:00:00'");

        EnsureColumnExists(db, "AsymmetricKeys", "KeyId", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "AsymmetricKeys", "AlgorithmCode", "TEXT NOT NULL DEFAULT 'RSA'");
        EnsureColumnExists(db, "AsymmetricKeys", "OwnerNode", "TEXT NOT NULL DEFAULT 'EQ01'");
        EnsureColumnExists(db, "AsymmetricKeys", "PublicKeyPem", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "AsymmetricKeys", "ProtectedPrivateKeyBase64", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "AsymmetricKeys", "ParametersJson", "TEXT NOT NULL DEFAULT '{}'");
        EnsureColumnExists(db, "AsymmetricKeys", "CreatedAtUtc", "TEXT NOT NULL DEFAULT '2026-01-01 00:00:00'");

        // Normalizar cualquier columna DateTime que haya quedado vacía ('') o NULL en registros antiguos
        db.Database.ExecuteSqlRaw("UPDATE Usuarios SET FechaRegistro = '2026-01-01 00:00:00' WHERE FechaRegistro IS NULL OR FechaRegistro = '';");
        db.Database.ExecuteSqlRaw("UPDATE RegistrosCifrados SET FechaOperacion = '2026-01-01 00:00:00' WHERE FechaOperacion IS NULL OR FechaOperacion = '';");
        db.Database.ExecuteSqlRaw("UPDATE SolicitudesEntrantes SET FechaRecepcion = '2026-01-01 00:00:00' WHERE FechaRecepcion IS NULL OR FechaRecepcion = '';");
        db.Database.ExecuteSqlRaw("UPDATE TrustedPeers SET LastSeenUtc = '2026-01-01 00:00:00' WHERE LastSeenUtc IS NULL OR LastSeenUtc = '';");
        db.Database.ExecuteSqlRaw("UPDATE SeenPackets SET PacketTimestampUtc = '2026-01-01 00:00:00' WHERE PacketTimestampUtc IS NULL OR PacketTimestampUtc = '';");
        db.Database.ExecuteSqlRaw("UPDATE SeenPackets SET ReceivedAtUtc = '2026-01-01 00:00:00' WHERE ReceivedAtUtc IS NULL OR ReceivedAtUtc = '';");
        db.Database.ExecuteSqlRaw("UPDATE AsymmetricKeys SET CreatedAtUtc = '2026-01-01 00:00:00' WHERE CreatedAtUtc IS NULL OR CreatedAtUtc = '';");

        // 4.b Verificar dinámicamente todas las propiedades escalares del modelo EF Core por reflexión del IModel
        EnsureAllEfModelColumnsExist(db);

        // 5. Reparar rutas RutaZipTemporal que apuntaban a bin\...\IncomingPackets\ y cuyo archivo fue consolidado en AppDataDirectory
        RepairLegacyZipPaths(db);

        // 6. Validar conexión y consulta real sobre las entidades
        if (!db.Database.CanConnect())
            throw new InvalidOperationException("SQLite CanConnect() devolvió false.");

        _ = db.Usuarios.Count();
        _ = db.RegistrosCifrados.Count();
        _ = db.SolicitudesEntrantes.Count();

        if (db.Usuarios.Any())
        {
            bool changed = false;
            foreach (var u in db.Usuarios.ToList())
            {
                if (!NodeRuntimeState.IsValidAnyVersionNodeId(u.NodoAsignado))
                {
                    u.NodoAsignado = NodeRuntimeState.CurrentNodeId;
                    changed = true;
                }
                if (string.IsNullOrWhiteSpace(u.NombreCompleto))
                {
                    u.NombreCompleto = u.NombreUsuario;
                    changed = true;
                }
            }
            if (changed) db.SaveChanges();
        }

        if (targetPath == DatabasePath && NodeRuntimeState.IsV2)
        {
            LoadPersistedPeersIntoRuntime(db);
        }
    }

    private static void EnsureAllEfModelColumnsExist(AppDbContext db)
    {
        foreach (var entityType in db.Model.GetEntityTypes())
        {
            string? tableName = entityType.GetTableName();
            if (string.IsNullOrWhiteSpace(tableName)) continue;

            foreach (var prop in entityType.GetProperties())
            {
                if (prop.IsPrimaryKey()) continue;
                string? colName = prop.GetColumnName();
                if (string.IsNullOrWhiteSpace(colName)) continue;

                Type clrType = Nullable.GetUnderlyingType(prop.ClrType) ?? prop.ClrType;
                bool isNullable = prop.IsNullable && clrType != typeof(string);
                string sqlDef = clrType == typeof(int) || clrType == typeof(long) || clrType == typeof(bool)
                    ? (isNullable ? "INTEGER NULL" : "INTEGER NOT NULL DEFAULT 0")
                    : (clrType == typeof(DateTime) ? "TEXT NOT NULL DEFAULT '2026-01-01 00:00:00'" : "TEXT NOT NULL DEFAULT ''");

                EnsureColumnExists(db, tableName, colName, sqlDef);
            }
        }
    }

    private static void RepairLegacyZipPaths(AppDbContext db)
    {
        try
        {
            bool anyUpdated = false;
            foreach (var sol in db.SolicitudesEntrantes.ToList())
            {
                if (string.IsNullOrWhiteSpace(sol.RutaZipTemporal)) continue;
                if (File.Exists(sol.RutaZipTemporal)) continue;

                string fileName = Path.GetFileName(sol.RutaZipTemporal);
                if (!string.IsNullOrWhiteSpace(fileName))
                {
                    string candidateInAppData = Path.Combine(IncomingPacketsDirectory, fileName);
                    if (File.Exists(candidateInAppData))
                    {
                        sol.RutaZipTemporal = candidateInAppData;
                        anyUpdated = true;
                    }
                }
            }
            if (anyUpdated)
                db.SaveChanges();
        }
        catch { }
    }

    public static void EnsureColumnExists(AppDbContext db, string table, string column, string sqlDefinition)
    {
        var conn = db.Database.GetDbConnection();
        bool wasClosed = conn.State != ConnectionState.Open;
        if (wasClosed) conn.Open();

        try
        {
            bool exists = false;
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = $"PRAGMA table_info(\"{table}\");";
                using var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    string colName = reader.GetString(1);
                    if (string.Equals(colName, column, StringComparison.OrdinalIgnoreCase))
                    {
                        exists = true;
                        break;
                    }
                }
            }

            if (!exists)
            {
                using var alterCmd = conn.CreateCommand();
                alterCmd.CommandText = $"ALTER TABLE \"{table}\" ADD COLUMN \"{column}\" {sqlDefinition};";
                alterCmd.ExecuteNonQuery();
            }
        }
        finally
        {
            if (wasClosed && conn.State == ConnectionState.Open)
                conn.Close();
        }
    }

    /// <summary>
    /// Ejecuta PRAGMA wal_checkpoint(TRUNCATE); para vaciar transacciones pendientes en -wal al archivo principal .db.
    /// </summary>
    public static void CheckpointWalTruncate(string? customDatabasePath = null)
    {
        string targetPath = string.IsNullOrWhiteSpace(customDatabasePath) ? DatabasePath : customDatabasePath;
        if (!File.Exists(targetPath)) return;

        using var conn = new SqliteConnection(BuildSqliteConnectionString(targetPath));
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
        cmd.ExecuteNonQuery();
        conn.Close();
        SqliteConnection.ClearPool(conn);
    }

    private static void BackupAndRecreateCorruptDatabase(string targetPath)
    {
        try
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(targetPath))
            {
                string backupPath = $"{targetPath}.bak.{DateTime.Now:yyyyMMdd_HHmmss}";
                File.Move(targetPath, backupPath, overwrite: true);
            }
            if (File.Exists(targetPath + "-shm")) File.Delete(targetPath + "-shm");
            if (File.Exists(targetPath + "-wal")) File.Delete(targetPath + "-wal");
        }
        catch { }
    }

    /// <summary>
    /// Ejecuta SELECT 1 y verifica el modo WAL sobre SQLite, devolviendo el diagnóstico real.
    /// </summary>
    public static bool TestConnection(out string diagnostic, string? customDatabasePath = null)
    {
        string targetPath = string.IsNullOrWhiteSpace(customDatabasePath) ? DatabasePath : customDatabasePath;
        try
        {
            using var conn = new SqliteConnection(BuildSqliteConnectionString(targetPath));
            conn.Open();

            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT 1;";
            object? scalar = cmd.ExecuteScalar();
            if (Convert.ToInt32(scalar) != 1)
            {
                diagnostic = $"Respuesta inesperada de SELECT 1 en {targetPath}";
                return false;
            }

            using var walCmd = conn.CreateCommand();
            walCmd.CommandText = "PRAGMA journal_mode;";
            string journalMode = (walCmd.ExecuteScalar()?.ToString() ?? "wal").ToUpperInvariant();

            diagnostic = $"Conectado (Modo {journalMode} activo) • {targetPath}";
            return true;
        }
        catch (Exception ex)
        {
            diagnostic = $"Error SQLite ({targetPath}): {ex.Message}";
            return false;
        }
    }

    public static void LoadPersistedPeersIntoRuntime(AppDbContext db)
    {
        var savedPeers = db.TrustedPeers.AsNoTracking().ToList();
        foreach (var saved in savedPeers)
        {
            var match = NodeRuntimeState.NetworkPeers.FirstOrDefault(p =>
                p.NodeId.Equals(saved.NodeId, StringComparison.OrdinalIgnoreCase));

            if (match != null)
            {
                if (saved.NodeId != NodeRuntimeState.CurrentNodeId)
                {
                    match.IpAddress = saved.IpAddress;
                    match.Port = saved.Port;
                    match.HttpsPort = saved.HttpsPort;
                    match.Source = saved.Source;
                    match.Status = saved.HasThumbprintMismatch ? "blocked" : saved.Status;
                }
                match.PinnedThumbprintSha256 = saved.PinnedThumbprintSha256;
                match.CertThumbprint = saved.CertThumbprint;
                match.CertificatePem = saved.CertificatePem;
                match.IsConfirmed = saved.IsConfirmed;
                match.HasThumbprintMismatch = saved.HasThumbprintMismatch;
                match.LastSeenUtc = saved.LastSeenUtc;
            }
            else
            {
                NodeRuntimeState.NetworkPeers.Add(saved);
            }
        }
    }

    public static void UpsertTrustedPeer(PeerNode peer, string? customDatabasePath = null)
    {
        using var db = new AppDbContext(customDatabasePath ?? DatabasePath);
        var entity = db.TrustedPeers.FirstOrDefault(p => p.NodeId == peer.NodeId);
        if (entity == null)
        {
            db.TrustedPeers.Add(new PeerNode
            {
                NodeId = peer.NodeId,
                TeamNumber = peer.TeamNumber,
                IpAddress = peer.IpAddress,
                Port = peer.Port,
                HttpsPort = peer.HttpsPort,
                RoleLabel = peer.RoleLabel,
                ProtocolType = peer.ProtocolType,
                Source = peer.Source,
                Status = peer.Status,
                LastLatency = peer.LastLatency,
                CertThumbprint = peer.CertThumbprint,
                PinnedThumbprintSha256 = peer.PinnedThumbprintSha256,
                CertificatePem = peer.CertificatePem,
                AlgorithmsJson = peer.AlgorithmsJson,
                IsConfirmed = peer.IsConfirmed,
                HasThumbprintMismatch = peer.HasThumbprintMismatch,
                LastSeenUtc = peer.LastSeenUtc
            });
        }
        else
        {
            entity.TeamNumber = peer.TeamNumber;
            entity.IpAddress = peer.IpAddress;
            entity.Port = peer.Port;
            entity.HttpsPort = peer.HttpsPort;
            entity.RoleLabel = peer.RoleLabel;
            entity.ProtocolType = peer.ProtocolType;
            entity.Source = peer.Source;
            entity.Status = peer.Status;
            entity.LastLatency = peer.LastLatency;
            entity.CertThumbprint = peer.CertThumbprint;
            entity.PinnedThumbprintSha256 = peer.PinnedThumbprintSha256;
            entity.CertificatePem = peer.CertificatePem;
            entity.AlgorithmsJson = peer.AlgorithmsJson;
            entity.IsConfirmed = peer.IsConfirmed;
            entity.HasThumbprintMismatch = peer.HasThumbprintMismatch;
            entity.LastSeenUtc = peer.LastSeenUtc;
        }
        db.SaveChanges();
    }

    public static string ComputeSha256(string input)
    {
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes);
    }
}
