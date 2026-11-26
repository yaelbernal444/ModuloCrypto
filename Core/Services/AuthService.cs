using ModuloCrypto.Core.Data;
using ModuloCrypto.Core.Models;
using ModuloCrypto.Core.Services;
using System.Security.Cryptography;
using System.Text;

namespace ModuloCrypto.Core.Services;

/// <summary>
/// Servicio de autenticación de operadores con PBKDF2-SHA256 (100,000 iteraciones + Salt aleatorio de 16 bytes),
/// comparación en tiempo constante (FixedTimeEquals) y limpieza de buffers en RAM (ZeroMemory).
/// </summary>
public static class AuthService
{
    private const string Pbkdf2Prefix = "PBKDF2$";
    private const int SaltSizeBytes = 16;
    private const int HashSizeBytes = 32;
    private const int Pbkdf2Iterations = 100_000;

    public static string HashPasswordPbkdf2(string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSizeBytes);
        byte[] pwdBytes = Encoding.UTF8.GetBytes(password);
        byte[] hash = Array.Empty<byte>();
        try
        {
            hash = Rfc2898DeriveBytes.Pbkdf2(
                pwdBytes,
                salt,
                Pbkdf2Iterations,
                HashAlgorithmName.SHA256,
                HashSizeBytes);

            return $"{Pbkdf2Prefix}{Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pwdBytes);
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    public static bool VerifyPassword(string password, string storedHash)
    {
        if (string.IsNullOrEmpty(password) || string.IsNullOrWhiteSpace(storedHash) ||
            !storedHash.StartsWith(Pbkdf2Prefix, StringComparison.Ordinal))
        {
            return false;
        }

        string[] parts = storedHash.Split('$');
        if (parts.Length != 3) return false;

        byte[] pwdBytes = Encoding.UTF8.GetBytes(password);
        byte[] salt = Array.Empty<byte>();
        byte[] expectedHash = Array.Empty<byte>();
        byte[] computedHash = Array.Empty<byte>();

        try
        {
            salt = Convert.FromBase64String(parts[1]);
            expectedHash = Convert.FromBase64String(parts[2]);
            computedHash = Rfc2898DeriveBytes.Pbkdf2(
                pwdBytes,
                salt,
                Pbkdf2Iterations,
                HashAlgorithmName.SHA256,
                expectedHash.Length);

            return CryptographicOperations.FixedTimeEquals(computedHash, expectedHash);
        }
        catch
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pwdBytes);
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(expectedHash);
            CryptographicOperations.ZeroMemory(computedHash);
        }
    }

    public static Usuario? Authenticate(string username, string password, string? customDatabasePath = null)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            return null;

        string normalized = username.Trim();

        using var db = new AppDbContext(customDatabasePath ?? AppDbContext.DatabasePath);
        var user = db.Usuarios.FirstOrDefault(u => u.NombreUsuario.ToLower() == normalized.ToLower());
        if (user == null)
            return null;

        return VerifyPassword(password, user.PasswordHash) ? user : null;
    }

    public static (bool Success, string Message, Usuario? User) Register(
        string nombreCompleto,
        string username,
        string password,
        string nodoAsignado = "EQ01",
        string rol = "Operador EQ01",
        string? customDatabasePath = null)
    {
        if (string.IsNullOrWhiteSpace(nombreCompleto) || nombreCompleto.Trim().Length < 3)
            return (false, "Ingresa tu nombre completo (mínimo 3 caracteres).", null);

        if (string.IsNullOrWhiteSpace(username) || username.Trim().Length < 3)
            return (false, "El nombre de usuario debe tener al menos 3 caracteres.", null);

        if (string.IsNullOrWhiteSpace(password) || password.Length < 4)
            return (false, "La contraseña debe tener al menos 4 caracteres.", null);

        string normalizedUser = username.Trim();
        string normalizedName = nombreCompleto.Trim();

        using var db = new AppDbContext(customDatabasePath ?? AppDbContext.DatabasePath);

        if (db.Usuarios.Any(u => u.NombreUsuario.ToLower() == normalizedUser.ToLower()))
            return (false, "Ese nombre de usuario ya está registrado.", null);

        var user = new Usuario
        {
            NombreCompleto = normalizedName,
            NombreUsuario = normalizedUser,
            PasswordHash = HashPasswordPbkdf2(password),
            NodoAsignado = NodeRuntimeState.IsValidNodeId(nodoAsignado) ? nodoAsignado.Trim().ToUpperInvariant() : NodeRuntimeState.CurrentNodeId,
            Rol = string.IsNullOrWhiteSpace(rol) ? "Operador EQ01" : rol.Trim(),
            FechaRegistro = DateTime.Now
        };

        db.Usuarios.Add(user);
        db.SaveChanges();

        return (true, "Integrante registrado correctamente.", user);
    }
}
