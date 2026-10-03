using SafeVault.Services;

namespace SafeVault.Tests;

public class InputValidationTests
{
    [Theory]
    [InlineData("alice")]
    [InlineData("Bob_99")]
    [InlineData("abc")]
    public void Valid_usernames_are_accepted(string username) =>
        Assert.True(InputSanitizer.IsValidUsername(username));

    [Theory]
    [InlineData("")]
    [InlineData("ab")]
    [InlineData("user name")]
    [InlineData("admin'--")]
    [InlineData("alice' OR '1'='1")]
    [InlineData("<script>alert(1)</script>")]
    [InlineData("a;DROP TABLE Users")]
    [InlineData("user\n")]
    public void Dangerous_or_bad_usernames_are_rejected(string username) =>
        Assert.False(InputSanitizer.IsValidUsername(username));

    [Fact]
    public void Null_values_are_rejected()
    {
        Assert.False(InputSanitizer.IsValidUsername(null));
        Assert.False(InputSanitizer.IsValidEmail(null));
        Assert.False(InputSanitizer.IsValidPassword(null));
    }

    [Theory]
    [InlineData("alice@example.com")]
    [InlineData("john.doe+tag@mail.example.org")]
    public void Valid_emails_are_accepted(string email) =>
        Assert.True(InputSanitizer.IsValidEmail(email));

    [Theory]
    [InlineData("not-an-email")]
    [InlineData("a@b")]
    [InlineData("x'@example.com")]
    [InlineData("a@b.com<script>")]
    [InlineData("<script>alert(1)</script>@example.com")]
    public void Bad_emails_are_rejected(string email) =>
        Assert.False(InputSanitizer.IsValidEmail(email));

    [Theory]
    [InlineData("short1", false)]
    [InlineData("onlyletterspassword", false)]
    [InlineData("12345678901", false)]
    [InlineData("Str0ngPassw0rd", true)]
    public void Password_rules_work(string password, bool expected) =>
        Assert.Equal(expected, InputSanitizer.IsValidPassword(password));

    [Fact]
    public void Password_longer_than_72_characters_is_rejected() =>
        Assert.False(InputSanitizer.IsValidPassword(new string('a', 72) + "1"));

    // ---------- XSS ----------

    [Fact]
    public void Sanitize_neutralizes_script_tags()
    {
        var result = InputSanitizer.Sanitize("<script>alert(\"XSS\")</script>");

        Assert.DoesNotContain("<script>", result);
        Assert.Equal("&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;", result);
    }

    [Theory]
    [InlineData("<img src=x onerror=alert(1)>")]
    [InlineData("<svg onload=alert(1)>")]
    [InlineData("\"><script>alert(1)</script>")]
    public void Sanitize_removes_dangerous_characters(string payload)
    {
        var result = InputSanitizer.Sanitize(payload);

        Assert.DoesNotContain("<", result);
        Assert.DoesNotContain(">", result);
    }

    [Fact]
    public void Sanitize_handles_null_empty_and_control_characters()
    {
        Assert.Equal(string.Empty, InputSanitizer.Sanitize(null));
        Assert.Equal(string.Empty, InputSanitizer.Sanitize(""));
        Assert.Equal("ab", InputSanitizer.Sanitize("a\0b\r\n"));
    }

    [Fact]
    public void Sanitize_keeps_normal_text()
    {
        Assert.Equal("Hello world", InputSanitizer.Sanitize("  Hello world "));
    }

    [Theory]
    [InlineData("' OR 1=1 --")]
    [InlineData("<script>alert(1)</script>")]
    [InlineData("x; DROP TABLE Users")]
    [InlineData("1 UNION SELECT password FROM Users")]
    public void Suspicious_patterns_are_detected(string input) =>
        Assert.True(InputSanitizer.ContainsSuspiciousPattern(input));

    [Theory]
    [InlineData("alice_01")]
    [InlineData("Hello world")]
    public void Normal_text_is_not_suspicious(string input) =>
        Assert.False(InputSanitizer.ContainsSuspiciousPattern(input));
}
