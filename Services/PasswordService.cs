namespace SafeVault.Services;

/// <summary>Password hashing with BCrypt (random salt included in every hash).</summary>
public static class PasswordService
{
    private const int WorkFactor = 11;

    public static string Hash(string password) =>
        BCrypt.Net.BCrypt.HashPassword(password, WorkFactor);

    public static bool Verify(string password, string passwordHash)
    {
        try
        {
            return BCrypt.Net.BCrypt.Verify(password, passwordHash);
        }
        catch (Exception)
        {
            // A broken or unexpected hash format must never grant access.
            return false;
        }
    }
}
