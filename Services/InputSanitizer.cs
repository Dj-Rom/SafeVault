using System.Net;
using System.Text.RegularExpressions;

namespace SafeVault.Services;

/// <summary>
/// Input validation and output encoding.
/// Validation uses a WHITELIST (only expected characters are allowed).
/// Sanitize() HTML-encodes text so it is safe to show in a web page (XSS protection).
/// </summary>
public static class InputSanitizer
{
    // \z (not $) so a trailing newline is not accepted.
    private static readonly Regex UsernameRegex =
        new(@"^[A-Za-z0-9_]{3,30}\z", RegexOptions.Compiled);

    private static readonly Regex EmailRegex =
        new(@"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,}\z", RegexOptions.Compiled);

    private static readonly Regex SuspiciousRegex = new(
        @"<\s*script|javascript:|\bon\w+\s*=|--|;|'|\bunion\b.+\bselect\b|\bdrop\b.+\btable\b|\bor\b\s+\d+\s*=\s*\d+",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>Remove control characters, trim, and HTML-encode.</summary>
    public static string Sanitize(string? input)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;

        var cleaned = new string(input.Where(c => !char.IsControl(c)).ToArray()).Trim();
        return WebUtility.HtmlEncode(cleaned);
    }

    public static bool IsValidUsername(string? value) =>
        value is not null && UsernameRegex.IsMatch(value);

    public static bool IsValidEmail(string? value) =>
        value is not null && value.Length <= 254 && EmailRegex.IsMatch(value);

    /// <summary>8-72 characters (BCrypt limit) with at least one letter and one digit.</summary>
    public static bool IsValidPassword(string? value) =>
        value is not null
        && value.Length is >= 8 and <= 72
        && value.Any(char.IsLetter)
        && value.Any(char.IsDigit);

    /// <summary>Extra signal used for logging attack attempts; not the main defense.</summary>
    public static bool ContainsSuspiciousPattern(string? value) =>
        !string.IsNullOrEmpty(value) && SuspiciousRegex.IsMatch(value);
}
