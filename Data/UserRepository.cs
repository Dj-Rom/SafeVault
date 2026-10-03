using Microsoft.Data.Sqlite;
using SafeVault.Models;

namespace SafeVault.Data;

/// <summary>
/// All SQL uses parameters (@name). User input is NEVER added to the SQL text,
/// so SQL injection is not possible here.
/// </summary>
public class UserRepository
{
    private readonly string _connectionString;

    public UserRepository(string connectionString)
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
            CREATE TABLE IF NOT EXISTS Users (
                Id           INTEGER PRIMARY KEY AUTOINCREMENT,
                Username     TEXT NOT NULL UNIQUE COLLATE NOCASE,
                Email        TEXT NOT NULL UNIQUE COLLATE NOCASE,
                PasswordHash TEXT NOT NULL,
                Role         TEXT NOT NULL
            );";
        command.ExecuteNonQuery();
    }

    /// <returns>false if the username or email already exists.</returns>
    public bool CreateUser(User user)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText =
            "INSERT INTO Users (Username, Email, PasswordHash, Role) VALUES (@username, @email, @hash, @role);";
        command.Parameters.AddWithValue("@username", user.Username);
        command.Parameters.AddWithValue("@email", user.Email);
        command.Parameters.AddWithValue("@hash", user.PasswordHash);
        command.Parameters.AddWithValue("@role", user.Role);

        try
        {
            command.ExecuteNonQuery();
            return true;
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19) // constraint violation
        {
            return false;
        }
    }

    public User? GetByUsername(string username)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT Id, Username, Email, PasswordHash, Role FROM Users WHERE Username = @username LIMIT 1;";
        command.Parameters.AddWithValue("@username", username);

        using var reader = command.ExecuteReader();
        return reader.Read() ? Map(reader) : null;
    }

    public List<User> SearchUsers(string term)
    {
        // Escape LIKE wildcards so "%" and "_" from the user are treated as normal text.
        var escaped = term.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");

        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT Id, Username, Email, PasswordHash, Role FROM Users " +
            "WHERE Username LIKE @pattern ESCAPE '\\' ORDER BY Username LIMIT 100;";
        command.Parameters.AddWithValue("@pattern", "%" + escaped + "%");

        var result = new List<User>();
        using var reader = command.ExecuteReader();
        while (reader.Read()) result.Add(Map(reader));
        return result;
    }

    private static User Map(SqliteDataReader r) => new()
    {
        Id = r.GetInt32(0),
        Username = r.GetString(1),
        Email = r.GetString(2),
        PasswordHash = r.GetString(3),
        Role = r.GetString(4)
    };
}
