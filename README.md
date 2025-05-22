# mySocialSecure API

A secure, modern RESTful API built with ASP.NET 8 for managing user accounts, authentication, feedback, and reporting. This API is designed to help users estimate and understand Social Security disability benefits while keeping their data secure.

---

## ✨ Features

* JWT-based authentication with refresh tokens
* Two-Factor Authentication (2FA)
* Secure password reset and email confirmation flows
* Role-based authorization with granular claim-level policies
* Rate limiting to protect critical endpoints
* Feedback submission and moderation
* Admin tools for managing users and roles
* Integrated Swagger documentation
* PostgreSQL database support
* MaxMind GeoLite2 IP geolocation service
* Email notifications using SMTP
* Complete xUnit test suite

---

## ⚙ Requirements

* [.NET 8 SDK](https://dotnet.microsoft.com/download)
* [PostgreSQL](https://www.postgresql.org/) (e.g., version 15)
* [.NET EF Core CLI tools](https://learn.microsoft.com/en-us/ef/core/cli/dotnet)
* Node.js (if using any frontend integration)
* Linux/macOS/Windows compatible

---

## 📁 Project Structure

```
mySocialSecureApi/
├── src/
│   └── mySocialSecureApi/             # Main API project
├── tests/
│   └── mySocialSecureApiTests/       # xUnit test project
│       └── config/
│           └── test.env              # Test-specific environment variables
├── config/
│   └── secrets.env                   # Runtime environment variables
├── App_Data/                         # GeoLite2 databases and certs
├── docs/                             # Swagger and documentation
└── README.md
```

---

## ⚡ Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/mySocialSecureApi.git
cd mySocialSecureApi
```

### 2. Create Required .env Files

#### `config/secrets.env`

```
POSTGRESQL_CONNECTION_STRING=Host=localhost;Port=5432;Database=mydb;Username=admin;Password=yourpassword
JWT_SECRET_KEY=your-super-secret-key
DEFAULT_ADMIN_EMAIL=admin@mysocialsecure.com
DEFAULT_ADMIN_PASSWORD=StrongPassword123!
EMAIL_PASSWORD=your-smtp-password
```

#### `tests/config/test.env`

```
MAXMIND_LICENSE_KEY=your-maxmind-license-key
```

> You can use `.env.example` if available to scaffold.

### 3. Apply Database Migrations

```bash
cd src/mySocialSecureApi
dotnet ef database update
```

### 4. Run the API

```bash
dotnet run --project src/mySocialSecureApi
```

The API should now be running at:

```
https://localhost:7119
```

---

## 📃 API Documentation

Once the API is running, navigate to the Swagger UI:

```
https://localhost:7119/docs
```

---

## 📚 Running Tests

```bash
dotnet test tests/mySocialSecureApiTests
```

This project uses [DotNetEnv](https://github.com/tonerdo/dotnet-env) to load environment variables in test environments. The tests automatically load `tests/config/test.env`.

---

## 👨‍💻 Developer Notes

* To modify rate limiting, edit policies in `Program.cs`
* To add new policies, see the `builder.Services.AddAuthorization` section
* Email templates are stored in `EmailTemplates/` and loaded dynamically
* Log files and correlation IDs are integrated for tracking and debugging

---

## 👥 Credits

Built by the mySocialSecure team ❤

Uses:

* ASP.NET Core 8
* Entity Framework Core
* MaxMind GeoLite2 (requires a license key)
* xUnit + Moq for testing
* Swagger / OpenAPI for docs

---

## ✉ Need Help?

Feel free to open an issue or pull request. Contributions and questions are welcome!
