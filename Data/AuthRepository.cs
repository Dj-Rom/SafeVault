using System.Globalization;
using Microsoft.Data.Sqlite;

namespace SafeVault.Data;

/// <summary>
/// Tracks failed logins and temporary account lockout (brute-force protection).
/// After 5 failed attempts the account is locked for 5 minutes.
/// </summary>
public class AuthRepository
{
    public const int MaxFailedAttempts = 5;
    public static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(5);

    private readonly string _connectionString;

    public AuthRepository(string connectionString)
    {
        _connectionString = connectionString;
        Initialize();
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        return connection;
    }

    private void Initialize()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = @"
            CREATE TABLE IF NOT EXISTS LoginAttempts (
                Username    TEXT PRIMARY KEY COLLATE NOCASE,
                FailedCount INTEGER NOT NULL,
                LockedUntil TEXT NULL
            );";
        command.ExecuteNonQuery();
    }

    public bool IsLockedOut(string username)
    {
        var lockedUntil = GetLockedUntil(username);
        if (lockedUntil is null) return false;
        if (lockedUntil > DateTime.UtcNow) return true;

        Reset(username); // the lock has expired
        return false;
    }

    public void RecordFailure(string username)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = @"
            INSERT INTO LoginAttempts (Username, FailedCount, LockedUntil)
            VALUES (@username, 1, NULL)
            ON CONFLICT(Username) DO UPDATE SET
                FailedCount = FailedCount + 1,
                LockedUntil = CASE WHEN FailedCount + 1 >= @max THEN @until ELSE LockedUntil END;";
        command.Parameters.AddWithValue("@username", username);
        command.Parameters.AddWithValue("@max", MaxFailedAttempts);
        command.Parameters.AddWithValue("@until", DateTime.UtcNow.Add(LockoutDuration).ToString("o"));
        command.ExecuteNonQuery();
    }

    public void Reset(string username)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM LoginAttempts WHERE Username = @username;";
        command.Parameters.AddWithValue("@username", username);
        command.ExecuteNonQuery();
    }

    private DateTime? GetLockedUntil(string username)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT LockedUntil FROM LoginAttempts WHERE Username = @username LIMIT 1;";
        command.Parameters.AddWithValue("@username", username);

        var value = command.ExecuteScalar();
        if (value is null || value is DBNull) return null;

        return DateTime.Parse((string)value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
    }
}
