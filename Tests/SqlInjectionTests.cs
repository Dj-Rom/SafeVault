using SafeVault.Data;
using SafeVault.Models;

namespace SafeVault.Tests;

/// <summary>
/// These tests call the repository directly (without the validator) to prove that
/// the SQL itself is safe, even if bad input reaches the database layer.
/// </summary>
public class SqlInjectionTests : IDisposable
{
    private readonly TestDb _db = new();
    private readonly UserRepository _repo;

    public SqlInjectionTests()
    {
        _repo = new UserRepository(_db.ConnectionString);
        _repo.CreateUser(new User { Username = "alice", Email = "alice@example.com", PasswordHash = "hash1" });
        _repo.CreateUser(new User { Username = "bob", Email = "bob@example.com", PasswordHash = "hash2" });
    }

    public void Dispose() => _db.Dispose();

    [Theory]
    [InlineData("alice' OR '1'='1")]
    [InlineData("' OR 1=1 --")]
    [InlineData("alice'--")]
    [InlineData("' UNION SELECT Id, Username, Email, PasswordHash, Role FROM Users --")]
    public void Injection_text_in_username_finds_nobody(string payload) =>
        Assert.Null(_repo.GetByUsername(payload));

    [Fact]
    public void Drop_table_payload_does_not_delete_the_table()
    {
        Assert.Null(_repo.GetByUsername("'; DROP TABLE Users; --"));

        // The table still exists and the data is still there.
        Assert.NotNull(_repo.GetByUsername("alice"));
        Assert.NotNull(_repo.GetByUsername("bob"));
    }

    [Fact]
    public void Injection_in_search_does_not_return_all_users() =>
        Assert.Empty(_repo.SearchUsers("' OR '1'='1"));

    [Fact]
    public void Like_wildcards_are_treated_as_normal_text()
    {
        Assert.Empty(_repo.SearchUsers("%"));
        Assert.Empty(_repo.SearchUsers("_"));
    }

    [Fact]
    public void Normal_search_works()
    {
        var result = _repo.SearchUsers("ali");

        Assert.Single(result);
        Assert.Equal("alice", result[0].Username);
    }

    [Fact]
    public void Duplicate_username_is_not_created() =>
        Assert.False(_repo.CreateUser(new User
        {
            Username = "ALICE",
            Email = "other@example.com",
            PasswordHash = "hash"
        }));
}
