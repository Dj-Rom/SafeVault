namespace SafeVault.Models;

public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string Role { get; set; } = Roles.User;
}

public static class Roles
{
    public const string Admin = "Admin";
    public const string User = "User";
}
