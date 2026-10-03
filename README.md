# SafeVault - Security Activities Report

## Overview

SafeVault is a small secure web API (ASP.NET Core 8, SQLite) for storing user accounts. The project shows how to protect an application against the most common web attacks: SQL injection, cross-site scripting (XSS), weak password storage, brute-force logins and broken access control.

The project includes secure coding practices, authentication, role-based authorization and an automated security test suite.

## How to run

Requirements: [.NET 8 SDK](https://dotnet.microsoft.com/download).

```bash
# run all tests
dotnet test SafeVault.sln

# run the app (creates a first admin user named "admin")
# PowerShell:  $env:Seed__AdminPassword = "ChangeMe123!"
export Seed__AdminPassword="ChangeMe123!"
export Jwt__Key="put-a-long-random-secret-here-at-least-32-characters"
dotnet run --project SafeVault.csproj
```

Endpoints:

| Method | Path | Access |
|--------|------|--------|
| POST | `/register` | public (new users always get the `User` role) |
| POST | `/login` | public, returns a JWT, locks the account after 5 failed attempts |
| GET | `/profile` | any logged-in user |
| GET | `/user/area` | `User` or `Admin` |
| GET | `/admin/dashboard?search=...` | `Admin` only |

---

## Vulnerabilities Identified

### 1. Cross-Site Scripting (XSS)

**Risk.** Text typed by a user was shown on a page without encoding. A value such as the following would run in another person's browser:

```
<script>alert("XSS")</script>
```

**Fix applied.** All user-controlled text goes through `InputSanitizer.Sanitize`, which removes control characters and HTML-encodes the value. Usernames and emails are also checked with strict whitelist rules, and the app sends security headers (`Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`).

```csharp
html.Append(InputSanitizer.Sanitize(search));
```

### 2. SQL Injection

**Risk.** SQL built by joining strings lets an attacker change the query:

```
' OR 1=1 --
```

**Fix applied.** Every query uses parameters, so input is always treated as data and never as SQL. `LIKE` wildcards are escaped as well.

```csharp
command.CommandText = "SELECT ... FROM Users WHERE Username = @username LIMIT 1;";
command.Parameters.AddWithValue("@username", username);
```

### 3. Insecure Password Storage

**Risk.** Plain-text or weakly hashed passwords are exposed if the database leaks.

**Fix applied.** Passwords are hashed with BCrypt (random salt, work factor 11) in `PasswordService`. Verification uses `BCrypt.Verify`, and a broken hash never grants access.

### 4. Brute-Force Login Attempts

**Risk.** An attacker can try thousands of passwords.

**Fix applied.** `AuthRepository` counts failed logins. After 5 failures the account is locked for 5 minutes. The login response is the same for a wrong password and an unknown user, and a dummy hash is verified for unknown users so the response time does not reveal valid usernames.

### 5. Unauthorized Access

**Risk.** Normal users could open administrator pages, or register themselves as administrators.

**Fix applied.** Role-based access control (RBAC) with the roles `Admin` and `User`. Admin routes use an `AdminOnly` policy, and `AuthorizationService` checks the role again from the database.

```csharp
authz.CanAccessAdminDashboard(user);
```

New accounts always get the `User` role, and the client cannot choose a role.

---

## Security Features Implemented

**Input validation:** username, email and password rules (whitelist), sanitizing and encoding of output.
**Secure database access:** parameterized queries only.
**Authentication:** BCrypt password hashing, signed JWT tokens (issuer, audience, expiry and signature are validated), account lockout.
**Authorization:** RBAC with protected admin routes; roles are assigned only on the server.

---

## Project Structure

```
SafeVault
│
├── Models
│   ├── User.cs
│   └── LoginRequest.cs
│
├── Data
│   ├── UserRepository.cs
│   └── AuthRepository.cs
│
├── Services
│   ├── InputSanitizer.cs
│   ├── PasswordService.cs
│   ├── AuthenticationService.cs
│   └── AuthorizationService.cs
│
├── Tests
│   ├── InputValidationTests.cs
│   ├── SqlInjectionTests.cs
│   ├── AuthenticationTests.cs
│   ├── AuthorizationTests.cs
│   └── ApiIntegrationTests.cs
│
├── Program.cs
└── appsettings.json
```

---

## Tests Implemented

Run them with `dotnet test SafeVault.sln`.

| Test file | What it checks |
|-----------|----------------|
| `InputValidationTests` | whitelist rules, XSS payloads such as `<script>`, `<img onerror>` and `<svg onload>` are neutralized |
| `SqlInjectionTests` | payloads such as `' OR 1=1 --` and `'; DROP TABLE Users; --` find nobody and the table survives |
| `AuthenticationTests` | valid and invalid login, BCrypt hash storage, lockout after 5 failures, new users always get the `User` role |
| `AuthorizationTests` | Admin can open the dashboard, User cannot, unknown or wrongly cased roles are refused |
| `ApiIntegrationTests` | the real HTTP API: 401 without a token, 403 for a normal user, 200 for an admin, tampered tokens rejected, XSS encoded in the dashboard |

---

## How Microsoft Copilot Assisted

<!-- EDIT THIS SECTION so it describes what you really did with Copilot. Keep only what is true. -->

Microsoft Copilot was used as an assistant during the project. It helped to:

1. Generate the first version of the input validation and sanitizing code.
2. Suggest parameterized SQL queries instead of string concatenation.
3. Suggest BCrypt for password hashing.
4. Draft the authentication and role-based authorization logic.
5. Generate test cases for XSS, SQL injection, authentication and authorization.
6. Point out vulnerable code and suggest fixes during debugging.

Every suggestion was reviewed, tested and adjusted before it was kept.

## Conclusion

SafeVault now has input validation, SQL injection protection, XSS output encoding, BCrypt password hashing, brute-force protection, JWT authentication and role-based authorization. The automated tests check each control against common attack payloads.
