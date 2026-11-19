using ModuloCrypto.Core.Data;
using ModuloCrypto.Core.Models;

namespace ModuloCrypto.Core.Services;

public static class AuthService
{
    public static Usuario? Authenticate(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            return null;

        string normalized = username.Trim();
        string hash = AppDbContext.ComputeSha256(password);

        using var db = new AppDbContext();
        return db.Usuarios.FirstOrDefault(u =>
            u.NombreUsuario.ToLower() == normalized.ToLower() &&
            u.PasswordHash == hash);
    }

    public static (bool Success, string Message, Usuario? User) Register(
        string username,
        string password,
        string nodoAsignado,
        string rol)
    {
        if (string.IsNullOrWhiteSpace(username) || username.Trim().Length < 3)
            return (false, "El nombre de usuario debe tener al menos 3 caracteres.", null);

        if (string.IsNullOrWhiteSpace(password) || password.Length < 4)
            return (false, "La contraseña debe tener al menos 4 caracteres.", null);

        string normalized = username.Trim();
        using var db = new AppDbContext();

        if (db.Usuarios.Any(u => u.NombreUsuario.ToLower() == normalized.ToLower()))
            return (false, "Ese nombre de usuario ya existe en SQLite.", null);

        var user = new Usuario
        {
            NombreUsuario = normalized,
            PasswordHash = AppDbContext.ComputeSha256(password),
            NodoAsignado = string.IsNullOrWhiteSpace(nodoAsignado) ? "NODO-04" : nodoAsignado.Trim().ToUpperInvariant(),
            Rol = string.IsNullOrWhiteSpace(rol) ? "Operador Tor" : rol.Trim(),
            FechaRegistro = DateTime.Now
        };

        db.Usuarios.Add(user);
        db.SaveChanges();

        return (true, "Operador registrado correctamente.", user);
    }
}
