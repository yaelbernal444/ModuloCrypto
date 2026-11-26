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
    public static string DatabasePath { get; private set; } = ResolveWritableDatabasePath();

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

    private static string ResolveWritableDatabasePath()
    {
        string primaryDir = AppContext.BaseDirectory;
        try
        {
            Directory.CreateDirectory(primaryDir);
            string probeFile = Path.Combine(primaryDir, $".write_probe_{Guid.NewGuid():N}.tmp");
            File.WriteAllText(probeFile, "ok");
            File.Delete(probeFile);
            return Path.Combine(primaryDir, "ModuloCrypto.db");
        }
        catch
        {
            string fallbackDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "ModuloCrypto");
            Directory.CreateDirectory(fallbackDir);
            return Path.Combine(fallbackDir, "ModuloCrypto.db");
        }
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
    }

    /// <summary>
    /// Inicializa y migra idempotentemente el esquema SQLite (con PRAGMAs WAL, verificación de todas las tablas y columnas
    /// y recuperación automática con respaldo .bak si la base de datos previa estuviera corrupta).
    /// </summary>
    public static void InitializeDatabase(string? customDatabasePath = null)
    {
        string targetPath = string.IsNullOrWhiteSpace(customDatabasePath) ? DatabasePath : customDatabasePath;

        try
        {
            ApplySchemaAndMigrations(targetPath);
        }
        catch
        {
            // Recuperación segura ante BD corrupta o esquema incompatible: respaldar como .bak.<timestamp> y recrear limpia
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

        // 1. EnsureCreated inicial
        db.Database.EnsureCreated();

        // 2. Activar PRAGMAs de estabilidad y concurrencia
        db.Database.ExecuteSqlRaw("PRAGMA journal_mode = WAL;");
        db.Database.ExecuteSqlRaw("PRAGMA busy_timeout = 5000;");
        db.Database.ExecuteSqlRaw("PRAGMA foreign_keys = ON;");

        // 3. CREATE TABLE IF NOT EXISTS para todas las tablas del contexto
        db.Database.ExecuteSqlRaw(@"
            CREATE TABLE IF NOT EXISTS Usuarios (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                NombreCompleto TEXT NOT NULL DEFAULT '',
                NombreUsuario TEXT NOT NULL UNIQUE,
                PasswordHash TEXT NOT NULL DEFAULT '',
                NodoAsignado TEXT NOT NULL DEFAULT 'EQ01',
                Rol TEXT NOT NULL DEFAULT 'Operador EQ01',
                FechaRegistro TEXT NOT NULL DEFAULT ''
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
                FechaOperacion TEXT NOT NULL DEFAULT ''
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
                FechaRecepcion TEXT NOT NULL DEFAULT ''
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
                LastSeenUtc TEXT NOT NULL DEFAULT ''
            );");

        db.Database.ExecuteSqlRaw(@"
            CREATE TABLE IF NOT EXISTS SeenPackets (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                PacketId TEXT NOT NULL UNIQUE,
                SourceNode TEXT NOT NULL DEFAULT '',
                PacketTimestampUtc TEXT NOT NULL DEFAULT '',
                ReceivedAtUtc TEXT NOT NULL DEFAULT ''
            );");

        // 4. Asegurar todas las columnas de cada tabla consultando PRAGMA table_info
        EnsureColumnExists(db, "Usuarios", "NombreCompleto", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "Usuarios", "NombreUsuario", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "Usuarios", "PasswordHash", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "Usuarios", "NodoAsignado", "TEXT NOT NULL DEFAULT 'EQ01'");
        EnsureColumnExists(db, "Usuarios", "Rol", "TEXT NOT NULL DEFAULT 'Operador EQ01'");
        EnsureColumnExists(db, "Usuarios", "FechaRegistro", "TEXT NOT NULL DEFAULT ''");

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
        EnsureColumnExists(db, "RegistrosCifrados", "FechaOperacion", "TEXT NOT NULL DEFAULT ''");

        EnsureColumnExists(db, "SolicitudesEntrantes", "PacketId", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "SolicitudesEntrantes", "NodoOrigen", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "SolicitudesEntrantes", "IpOrigen", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "SolicitudesEntrantes", "NombreZip", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "SolicitudesEntrantes", "AlgoritmoCodigo", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "SolicitudesEntrantes", "FirmaX509Valida", "INTEGER NOT NULL DEFAULT 0");
        EnsureColumnExists(db, "SolicitudesEntrantes", "RutaZipTemporal", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "SolicitudesEntrantes", "Estado", "TEXT NOT NULL DEFAULT 'Pendiente'");
        EnsureColumnExists(db, "SolicitudesEntrantes", "FechaRecepcion", "TEXT NOT NULL DEFAULT ''");

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
        EnsureColumnExists(db, "TrustedPeers", "LastSeenUtc", "TEXT NOT NULL DEFAULT ''");

        EnsureColumnExists(db, "SeenPackets", "SourceNode", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "SeenPackets", "PacketTimestampUtc", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists(db, "SeenPackets", "ReceivedAtUtc", "TEXT NOT NULL DEFAULT ''");

        // 5. Validar conexión y consulta real sobre las entidades
        if (!db.Database.CanConnect())
            throw new InvalidOperationException("SQLite CanConnect() devolvió false.");

        _ = db.Usuarios.Count();
        _ = db.RegistrosCifrados.Count();
        _ = db.SolicitudesEntrantes.Count();

        // Actualizar usuarios previos al formato EQ01
        if (db.Usuarios.Any())
        {
            bool changed = false;
            foreach (var u in db.Usuarios.ToList())
            {
                if (!NodeRuntimeState.IsValidNodeId(u.NodoAsignado))
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

        if (targetPath == DatabasePath)
        {
            LoadPersistedPeersIntoRuntime(db);
        }
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
        var savedPeers = db.TrustedPeers.ToList();
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
