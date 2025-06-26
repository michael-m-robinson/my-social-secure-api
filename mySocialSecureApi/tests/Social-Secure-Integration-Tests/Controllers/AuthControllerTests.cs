using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using My_Social_Secure_Api.Data;
using My_Social_Secure_Api.Enums.Common;
using My_Social_Secure_Api.Interfaces.Services.Auth;
using My_Social_Secure_Api.Models.Auth;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Auth;
using My_Social_Secure_Api.Models.Dtos.Common;
using My_Social_Secure_Api.Models.Dtos.Registration;
using My_Social_Secure_Api.Models.Identity;
using Social_Secure_Integration_Tests.Infrastructure;
using Xunit.Abstractions;

#pragma warning disable CS9107 // Parameter is captured into the state of the enclosing type and its value is also passed to the base constructor. The value might be captured by the base class as well.


namespace Social_Secure_Integration_Tests.Controllers;

public class AuthControllerTests(CustomWebApplicationFactory factory, ITestOutputHelper output)
    : IntegrationTestBase(factory, output)
{
    [Fact]
    public async Task Register_ValidInput_ReturnsSuccess()
    {
        var requestBody = new
        {
            userName = "testuser",
            email = "testuser@example.com",
            firstName = "Test",
            lastName = "User",
            city = "Springfield",
            state = "MA",
            benefitType = "SSDI",
            password = "ValidPassword123!",
            confirmPassword = "ValidPassword123!",
            twoFactorEnabled = true,

            insurances = new[]
            {
                new { providerName = "Medicaid", isFederal = true }
            },

            receivesUtilityAid = true,
            utilityAids = new[]
            {
                new { aidType = "Electric", estimatedAmount = 75 }
            },

            hasWorkedBefore = true,
            workedInLastFiveYears = true,
            earningsLastFiveYears = 25000m,
            trialWorkMonthsUsed = 3,
            trialWorkPeriodEnded = false,

            hasNewJob = true,
            estimatedMonthlyIncome = 1200m,
            savedForFutureUse = true,
        };

        var request = new
        {
            Url = "/auth/register",
            Body = requestBody
        };

        var response = await Client.PostAsJsonAsync(request.Url, request.Body);

        var responseData = await response.Content.ReadFromJsonAsync<ApiResponse<RegisterDto>>();
        Assert.NotNull(responseData);
        Assert.Equal("Registration successful.", responseData.Message);
        Assert.True(responseData.Success);
    }

    [Fact]
    public async Task Register_InvalidInput_ReturnsBadRequest()
    {
        var requestBody = new
        {
            userName = "new-test-user",
            email = "invalid-email", // Invalid email format
            firstName = "Test",
            lastName = "User",
            city = "Springfield",
            state = "MA",
            benefitType = "SSDI",
            password = "ValidPassword123!",
            confirmPassword = "ValidPassword123!",
            twoFactorEnabled = true,
        };

        var request = new
        {
            Url = "/auth/register",
            Body = requestBody
        };

        var response = await Client.PostAsJsonAsync(request.Url, request.Body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var responseData = await response.Content.ReadFromJsonAsync<ApiResponse<RegisterDto>>();
        Assert.NotNull(responseData);
        Assert.False(responseData.Success);
        Assert.Contains("Invalid email format.", responseData.Error!.Errors!);
    }

    [Fact]
    public async Task Register_EmptyInput_ReturnsBadRequest()
    {
        var requestBody = new
        {
            userName = "",
            email = "",
            firstName = "",
            lastName = "",
            city = "",
            state = "",
            benefitType = "",
            password = "",
            confirmPassword = "",
            twoFactorEnabled = false,
        };

        var request = new
        {
            Url = "/auth/register",
            Body = requestBody
        };

        var response = await Client.PostAsJsonAsync(request.Url, request.Body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var errors = await response.Content.ReadFromJsonAsync<ValidationProblemDetails>();
        Assert.Contains("Email", errors!.Errors.Keys);
        Assert.Contains("UserName", errors.Errors.Keys);
        Assert.Contains("FirstName", errors.Errors.Keys);
        Assert.Contains("LastName", errors.Errors.Keys);
        Assert.Contains("City", errors.Errors.Keys);
        Assert.Contains("State", errors.Errors.Keys);
        Assert.Contains("BenefitType", errors.Errors.Keys);
        Assert.Contains("Password", errors.Errors.Keys);
        Assert.Contains("ConfirmPassword", errors.Errors.Keys);
    }

    [Fact]
    public async Task Register_UsernameAlreadyExists_ReturnsBadRequest()
    {
        var requestBody = new
        {
            userName = "existingEmailUser",
            email = "new@user.com",
            firstName = "Test",
            lastName = "User",
            city = "Springfield",
            state = "MA",
            benefitType = "SSDI",
            password = "ValidPassword123!",
            confirmPassword = "ValidPassword123!",
            twoFactorEnabled = true,
            insurances = new[]
            {
                new { providerName = "Medicaid", isFederal = true }
            },
            receivesUtilityAid = true,
            utilityAids = new[]
            {
                new { aidType = "Electric", estimatedAmount = 75 }
            },
            hasWorkedBefore = true,
            workedInLastFiveYears = true,
            earningsLastFiveYears = 25000m,
            trialWorkMonthsUsed = 3,
            trialWorkPeriodEnded = false,
            hasNewJob = true,
            estimatedMonthlyIncome = 1200m,
            savedForFutureUse = true,
        };

        var request = new
        {
            Url = "/auth/register",
            Body = requestBody
        };

        var response = await Client.PostAsJsonAsync(request.Url, request.Body);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var responseData = await response.Content.ReadFromJsonAsync<ApiResponse<RegisterDto>>();
        Assert.NotNull(responseData);
        Assert.False(responseData.Success);
        Assert.Equal(OperationStatus.Failed, responseData.Error!.Status);
        Assert.Equal(ErrorCategory.Authentication, responseData.Error!.Category);
        Assert.Equal("Authentication failed.", responseData.Error.Description);
        Assert.Equal("USERNAME_IN_USE", responseData.Error.Code);
        Assert.Contains("Username is already in use.", responseData.Error!.Errors!);
    }

    [Fact]
    public async Task Register_PasswordsDoNotMatch_ReturnsBadRequest()
    {
        var requestBody = new
        {
            userName = "testuser",
            email = "invalid-email", // Invalid email format
            firstName = "Test",
            lastName = "User",
            city = "Springfield",
            state = "MA",
            benefitType = "SSDI",
            password = "ValidPassword123!",
            confirmPassword = "ValidPassword1234!",
            twoFactorEnabled = true,
        };

        var request = new
        {
            Url = "/auth/register",
            Body = requestBody
        };

        var response = await Client.PostAsJsonAsync(request.Url, request.Body);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var responseData = await response.Content.ReadFromJsonAsync<ApiResponse<RegisterDto>>();
        Assert.NotNull(responseData);
        Assert.False(responseData.Success);
        Assert.Equal(OperationStatus.Failed, responseData.Error!.Status);
        Assert.Equal(ErrorCategory.Authentication, responseData.Error!.Category);
        Assert.Equal("Authentication failed.", responseData.Error.Description);
        Assert.Equal("PASSWORD_MISMATCH", responseData.Error.Code);
        Assert.Contains("Password and confirm password do not match.", responseData.Error!.Errors!);
    }

    [Fact]
    public async Task Login_Successful_ReturnsToken()
    {
        var client = CreateClientWithCookies(out _);

        var loginBody = new
        {
            userName = "TestUserNo2FA",
            password = "Password123!",
            rememberMe = false
        };

        var response = await client.PostAsJsonAsync("/auth/login", loginBody);
        var content = await response.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(content!.Success);
        Assert.NotNull(content.Data!.Token);
    }

    [Fact]
    public async Task Login_Requires2FA_ReturnsErrorWithCode()
    {
        var client = CreateClientWithCookies(out _);

        var loginBody = new
        {
            userName = "LoggedInUser2", // Must be configured for 2FA
            password = "Password123!",
            rememberMe = false
        };

        var response = await client.PostAsJsonAsync("/auth/login", loginBody);
        var content = await response.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(content!.Success);
        Assert.Equal("REQUIRES_2FA", content.Error?.Code);
    }

    [Fact]
    public async Task Login_EmailNotConfirmed_ReturnsNotAllowed()
    {
        var client = CreateClientWithCookies(out _);

        var loginBody = new
        {
            userName = "UnconfirmedEmailUser",
            password = "Password123!",
            rememberMe = false
        };

        var response = await client.PostAsJsonAsync("/auth/login", loginBody);
        var content = await response.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(content!.Success);
        Assert.Equal("EMAIL_NOT_CONFIRMED", content.Error?.Code);
    }

    [Fact]
    public async Task Login_InvalidPassword_ReturnsAuthFailure()
    {
        var client = CreateClientWithCookies(out _);

        var loginBody = new
        {
            userName = "LoggedInUser2",
            password = "WrongPassword!",
            rememberMe = false
        };

        var response = await client.PostAsJsonAsync("/auth/login", loginBody);
        var content = await response.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(content!.Success);
        Assert.Equal("LOGIN_FAILED", content.Error?.Code);
    }

    [Fact]
    public async Task LoginWith2Fa_TooManyFailedAttempts_LocksUser()
    {
        var client = Factory.CreateClient();
        client.BaseAddress = new Uri("http://localhost");

        // STEP 1: Perform login to initiate 2FA
        var loginRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/login")
        {
            Content = JsonContent.Create(new
            {
                userName = "LoggedInUser2",
                password = "Password123!",
                rememberMe = false,
                host = new { value = "localhost" },
                scheme = "http"
            })
        };

        var loginResponse = await client.SendAsync(loginRequest);
        Assert.Equal(HttpStatusCode.Unauthorized, loginResponse.StatusCode);

        var loginContent = await loginResponse.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();
        Assert.Equal("REQUIRES_2FA", loginContent!.Error?.Code);

        // STEP 2: Extract the 2FA cookie manually
        var setCookieHeader = loginResponse.Headers.GetValues("Set-Cookie")
            .FirstOrDefault(x => x.StartsWith(".AspNetCore.Identity.TwoFactorUserId"));

        Assert.NotNull(setCookieHeader);
        var twoFaCookie = setCookieHeader!.Split(';')[0]; // Get just the cookie name=value

        // STEP 3: Send 5 invalid 2FA requests with cookie header manually set
        for (int i = 0; i < 5; i++)
        {
            var twoFaRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/login-2fa")
            {
                Content = JsonContent.Create(new
                {
                    userName = "LoggedInUser2",
                    code = "WrongCode",
                    rememberMe = false,
                    host = new { value = "localhost" }
                })
            };

            twoFaRequest.Headers.Add("Cookie", twoFaCookie);

            var twoFaResponse = await client.SendAsync(twoFaRequest);
            var result = await twoFaResponse.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();

            Assert.False(result!.Success);
            Assert.Equal(i < 4 ? "INVALID_2FA_CODE" : "ACCOUNT_LOCKED", result.Error?.Code);
        }

        // STEP 4: Verify lockout in UserManager
        using var scope = Factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await userManager.FindByNameAsync("LoggedInUser2");

        Assert.True(await userManager.IsLockedOutAsync(user!));
    }

    [Fact]
    public async Task LoginWith2Fa_ValidCode_ReturnsSuccess()
    {
        var client = Factory.CreateClient();
        client.BaseAddress = new Uri("http://localhost");

        // Step 1: Trigger 2FA login
        var loginResponse = await client.PostAsJsonAsync("/auth/login", new
        {
            userName = "LoggedInUser2",
            password = "Password123!",
            rememberMe = false,
            host = new { value = "localhost" },
            scheme = "http"
        });

        Assert.Equal(HttpStatusCode.Unauthorized, loginResponse.StatusCode);

        var loginContent = await loginResponse.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();
        Assert.Equal("REQUIRES_2FA", loginContent?.Error?.Code);

        // Step 2: Extract .AspNetCore.Identity.TwoFactorUserId cookie
        var cookie = loginResponse.Headers
            .GetValues("Set-Cookie")
            .FirstOrDefault(h => h.StartsWith(".AspNetCore.Identity.TwoFactorUserId"));
        Assert.NotNull(cookie);
        var twoFaCookie = cookie!.Split(';')[0];

        // Step 3: Generate valid 2FA code using SignInManager
        using var scope = Factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await userManager.FindByNameAsync("LoggedInUser2");
        var code = await userManager.GenerateTwoFactorTokenAsync(user!, "Email");
        Assert.False(string.IsNullOrWhiteSpace(code));

        // Step 4: Submit the 2FA code
        var twoFaRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/login-2fa")
        {
            Content = JsonContent.Create(new
            {
                userName = "LoggedInUser2",
                code = code,
                rememberMe = false,
                host = new { value = "localhost" }
            })
        };
        twoFaRequest.Headers.Add("Cookie", twoFaCookie);

        var twoFaResponse = await client.SendAsync(twoFaRequest);
        var result = await twoFaResponse.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();

        // Step 5: Validate response
        Assert.Equal(HttpStatusCode.OK, twoFaResponse.StatusCode);
        Assert.True(result!.Success);
        Assert.Equal(OperationStatus.Ok, result.Data!.Status);
        Assert.Equal("The user was successfully authenticated.", result.Data.Description);
        Assert.False(string.IsNullOrWhiteSpace(result.Data.Token));
    }

    [Fact]
    public async Task LoginWith2Fa_MissingCookie_ReturnsUserNotFound()
    {
        var client = Client;

        var twoFaResponse = await client.PostAsJsonAsync("/auth/login-2fa", new
        {
            userName = "LoggedInUser2",
            password = "Password123!",
            code = "123456",
            rememberMe = false
        });

        var result = await twoFaResponse.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();
        Assert.False(result!.Success);
        Assert.Equal("USER_NOT_FOUND", result.Error?.Code);
        Assert.Equal("User not found.", result.Message);
    }

    [Fact]
    public async Task LoginWith2Fa_InvalidCode_ReturnsInvalidCodeError()
    {
        var client = Factory.CreateClient();
        client.BaseAddress = new Uri("http://localhost");

        // Step 1: Trigger login to get 2FA cookie
        var loginResponse = await client.PostAsJsonAsync("/auth/login", new
        {
            userName = "LoggedInUser2",
            password = "Password123!",
            rememberMe = false,
            host = new { value = "localhost" },
            scheme = "http"
        });

        Assert.Equal(HttpStatusCode.Unauthorized, loginResponse.StatusCode);
        var cookie = loginResponse.Headers
            .GetValues("Set-Cookie")
            .FirstOrDefault(x => x.StartsWith(".AspNetCore.Identity.TwoFactorUserId"));
        Assert.NotNull(cookie);
        var twoFaCookie = cookie!.Split(';')[0];

        // Step 2: Submit bad 2FA code
        var twoFaRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/login-2fa")
        {
            Content = JsonContent.Create(new
            {
                userName = "LoggedInUser2",
                code = "000000", // wrong
                rememberMe = false,
                host = new { value = "localhost" }
            })
        };
        twoFaRequest.Headers.Add("Cookie", twoFaCookie);

        var response = await client.SendAsync(twoFaRequest);
        var result = await response.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();

        Assert.False(result!.Success);
        Assert.Equal("INVALID_2FA_CODE", result.Error?.Code);
        Assert.Equal(OperationStatus.Failed, result.Error?.Status);
    }

    [Fact]
    public async Task ResendEmailConfirmation_ValidRequest_ReturnsSuccess()
    {
        var client = Factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("http://localhost")
        });

        var requestBody = new
        {
            email = "unconfirmed@example.com",
            scheme = "http",
            host = "localhost",
            userId = "placeholder"
        };

        var response = await client.PostAsJsonAsync("/auth/resend-email-confirmation", requestBody);
        var raw = await response.Content.ReadAsStringAsync();

        Output.WriteLine($"STATUS: {response.StatusCode}");
        Output.WriteLine("BODY:");
        Output.WriteLine(raw);

        var content = JsonSerializer.Deserialize<ApiResponse<OperationDto>>(raw, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(content!.Success);
        Assert.Equal(OperationStatus.Ok, content.Data!.Status);
        Assert.Equal("Email confirmation resent.", content.Message);
        Assert.Equal("Confirmation email resent successfully.", content.Data.Description);
    }

    [Fact]
    public async Task ResendEmailConfirmation_EmailAlreadyConfirmed_ReturnsValidationError()
    {
        var client = Factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("http://localhost")
        });

        var requestBody = new
        {
            email = "no2fa@example.com", // already confirmed
            scheme = "http",
            host = "localhost",
            userId = "placeholder"
        };

        var response = await client.PostAsJsonAsync("/auth/resend-email-confirmation", requestBody);
        var raw = await response.Content.ReadAsStringAsync();

        Output.WriteLine($"STATUS: {response.StatusCode}");
        Output.WriteLine("BODY:");
        Output.WriteLine(raw);

        var content = JsonSerializer.Deserialize<ApiResponse<OperationDto>>(raw, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(content!.Success);
        Assert.NotNull(content.Error);
        Assert.Equal("EMAIL_ALREADY_CONFIRMED", content.Error!.Code);
        Assert.Equal("Some fields contain invalid or missing values.", content.Error.Description);
        Assert.Contains("Email already confirmed.", content.Error.Errors!);
    }

    [Fact]
    public async Task ResendEmailConfirmation_UserNotFound_ReturnsNotFoundError()
    {
        var client = Factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("http://localhost")
        });

        var requestBody = new
        {
            email = "notarealuser@example.com",
            scheme = "http",
            host = "localhost",
            userId = "placeholder"
        };

        var response = await client.PostAsJsonAsync("/auth/resend-email-confirmation", requestBody);
        var raw = await response.Content.ReadAsStringAsync();

        var content = JsonSerializer.Deserialize<ApiResponse<OperationDto>>(raw, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(content!.Success);
        Assert.NotNull(content.Error);
        Assert.Equal("USER_NOT_FOUND", content.Error!.Code);
        Assert.Equal("The resource you're trying to access was not found.", content.Error.Description);
        Assert.Contains("User not found.", content.Error.Errors!);
    }

    [Fact]
    public async Task ConfirmEmail_ValidToken_ReturnsSuccess()
    {
        using var scope = Factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await userManager.FindByNameAsync("UnconfirmedEmailUser");

        var token = await userManager.GenerateEmailConfirmationTokenAsync(user!);

        var client = Client;
        var requestBody = new
        {
            userId = user!.Id,
            token = token
        };

        var response = await client.PostAsJsonAsync("/auth/confirm-email", requestBody);
        var raw = await response.Content.ReadAsStringAsync();

        Assert.False(string.IsNullOrWhiteSpace(raw));

        var content = JsonSerializer.Deserialize<ApiResponse<OperationDto>>(raw, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(content!.Success);
        Assert.Equal(OperationStatus.Ok, content.Data!.Status);
        Assert.Equal("Email confirmed successfully.", content.Message);
    }

    [Fact]
    public async Task ConfirmEmail_InvalidToken_ReturnsFailure()
    {
        using var scope = Factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await userManager.FindByNameAsync("UnconfirmedEmailUser");

        var client = Client;
        var requestBody = new
        {
            userId = user!.Id,
            token = "invalid-token"
        };

        var response = await client.PostAsJsonAsync("/auth/confirm-email", requestBody);
        var raw = await response.Content.ReadAsStringAsync();

        Assert.False(string.IsNullOrWhiteSpace(raw));

        var content = JsonSerializer.Deserialize<ApiResponse<OperationDto>>(raw, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(content!.Success);
        Assert.Equal("EMAIL_CONFIRMATION_FAILED", content.Error?.Code);
        Assert.Equal("We couldn’t verify your email. The link may have expired or already been used.",
            content.Error?.Description);
    }

    [Fact]
    public async Task ConfirmEmail_UserNotFound_ReturnsError()
    {
        var client = Client;
        var requestBody = new
        {
            userId = Guid.NewGuid().ToString(),
            token = "anytoken"
        };

        var response = await client.PostAsJsonAsync("/auth/confirm-email", requestBody);
        var raw = await response.Content.ReadAsStringAsync();

        Assert.False(string.IsNullOrWhiteSpace(raw));

        var content = JsonSerializer.Deserialize<ApiResponse<OperationDto>>(raw, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(content!.Success);
        Assert.Equal("USER_NOT_FOUND", content.Error?.Code);
        Assert.Contains("User not found.", content.Error?.Errors!);
    }

    [Fact]
    public async Task Refresh_ValidToken_ReturnsNewAccessToken()
    {
        using var scope = Factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var refreshService = scope.ServiceProvider.GetRequiredService<IRefreshTokenService>();

        var user = await userManager.FindByNameAsync("TestUserNo2FA");
        var refreshResponse = await refreshService.CreateRefreshTokenAsync(user!);
        Assert.True(refreshResponse.Success);

        var client = Client;
        var requestBody = new
        {
            refreshToken = refreshResponse.Data!.Token
        };

        var response = await client.PostAsJsonAsync("/auth/refresh", requestBody);
        var content = await response.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(content!.Success);
        Assert.Equal(OperationStatus.Ok, content.Data!.Status);
        Assert.Equal("Token rotation completed.", content.Message);
        Assert.False(string.IsNullOrWhiteSpace(content.Data!.Token));
    }

    [Fact]
    public async Task Refresh_InvalidToken_ReturnsUnauthorized()
    {
        var client = Client;
        var requestBody = new { refreshToken = "invalid-token-123" };

        var response = await client.PostAsJsonAsync("/auth/refresh", requestBody);
        var content = await response.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(content!.Success);
        Assert.Equal("INVALID_REFRESH_TOKEN",
            content.Error?.Code ?? content.Error?.Code); // if your controller maps to this
        Assert.Contains("invalid", content.Error?.Errors?.FirstOrDefault()?.ToLower());
    }

    [Fact]
    public async Task Refresh_RevokedToken_ReturnsUnauthorized()
    {
        using var scope = Factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var refreshService = scope.ServiceProvider.GetRequiredService<IRefreshTokenService>();

        var user = await userManager.FindByNameAsync("TestUserNo2FA");
        var refreshResponse = await refreshService.CreateRefreshTokenAsync(user!);

        // Revoke it
        var token = await db.RefreshTokens.FirstOrDefaultAsync(rt => rt.Token == refreshResponse.Data!.Token);
        token!.IsRevoked = true;
        await db.SaveChangesAsync();

        var client = Client;
        var requestBody = new { refreshToken = refreshResponse.Data!.Token };

        var response = await client.PostAsJsonAsync("/auth/refresh", requestBody);
        var content = await response.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(content!.Success);
        Assert.Equal("INVALID_REFRESH_TOKEN", content.Error?.Code);
    }

    [Fact]
    public async Task Refresh_ReusedToken_ReturnsUnauthorized()
    {
        using var scope = Factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var refreshService = scope.ServiceProvider.GetRequiredService<IRefreshTokenService>();

        var user = await userManager.FindByNameAsync("TestUserNo2FA");
        var tokenResult = await refreshService.CreateRefreshTokenAsync(user!);
        var refreshToken = tokenResult.Data!.Token;

        // Validate and rotate the token
        await refreshService.ValidateAndRotateRefreshTokenAsync(refreshToken!);

        var client = Client;
        var response = await client.PostAsJsonAsync("/auth/refresh", new { refreshToken });

        var content = await response.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(content!.Success);
        Assert.Equal("INVALID_REFRESH_TOKEN", content.Error?.Code);
        Assert.Contains("invalid", content.Error?.Errors?.FirstOrDefault()?.ToLower());
    }

    [Fact]
    public async Task Refresh_ExpiredToken_ReturnsUnauthorized()
    {
        using var scope = Factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        var user = await userManager.FindByNameAsync("TestUserNo2FA");
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

        db.RefreshTokens.Add(new RefreshTokenModel
        {
            UserId = user!.Id,
            Token = token,
            ExpiresUtc = DateTime.UtcNow.AddMinutes(-10), // expired
            IsRevoked = false
        });

        await db.SaveChangesAsync();

        var client = Client;
        var response = await client.PostAsJsonAsync("/auth/refresh", new { refreshToken = token });

        var content = await response.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(content!.Success);
        Assert.Equal("INVALID_REFRESH_TOKEN", content.Error?.Code);
    }

    [Fact]
    public async Task Refresh_TokenRotation_PreventsReuse()
    {
        using var scope = Factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var refreshService = scope.ServiceProvider.GetRequiredService<IRefreshTokenService>();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        var user = await userManager.FindByNameAsync("TestUserNo2FA");

        // STEP 1: Create refresh token manually
        var refreshTokenResponse = await refreshService.CreateRefreshTokenAsync(user!);
        var originalToken = refreshTokenResponse.Data!.Token;

        // STEP 2: Use it to refresh
        var client = Client;
        var refreshResponse = await client.PostAsJsonAsync("/auth/refresh", new { refreshToken = originalToken });

        var refreshContent = await refreshResponse.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();
        Assert.Equal(HttpStatusCode.OK, refreshResponse.StatusCode);
        Assert.True(refreshContent!.Success);
        Assert.False(string.IsNullOrWhiteSpace(refreshContent.Data!.Token));

        // STEP 3: Attempt reuse
        var secondUseResponse = await client.PostAsJsonAsync("/auth/refresh", new { refreshToken = originalToken });
        var secondUseContent = await secondUseResponse.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();

        Assert.Equal(HttpStatusCode.Unauthorized, secondUseResponse.StatusCode);
        Assert.False(secondUseContent!.Success);
        Assert.Equal("INVALID_REFRESH_TOKEN", secondUseContent.Error?.Code);
    }

    [Fact]
    public async Task Refresh_TokenRotationLog_IsPersisted()
    {
        // Arrange
        using var scope = Factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var refreshService = scope.ServiceProvider.GetRequiredService<IRefreshTokenService>();
        var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        var user = await userManager.FindByNameAsync("TestUserNo2FA");
        var refreshResponse = await refreshService.CreateRefreshTokenAsync(user!);
        Assert.True(refreshResponse.Success);

        var oldToken = refreshResponse.Data!.Token;

        var client = Client;
        var requestBody = new { refreshToken = oldToken };

        // Act
        var response = await client.PostAsJsonAsync("/auth/refresh", requestBody);
        var result = await response.Content.ReadFromJsonAsync<ApiResponse<TokenDto>>();

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(result!.Success);
        Assert.False(string.IsNullOrWhiteSpace(result.Data!.Token));
        Assert.NotEqual(oldToken, result.Data.Token);

        // Verify log was created
        var logEntry = await dbContext.TokenRotationLogs
            .Where(l => l.OldToken == oldToken && l.NewToken == result.Data.Token)
            .FirstOrDefaultAsync();

        Assert.NotNull(logEntry);
        Assert.Equal(user!.Id, logEntry!.UserId);
        Assert.False(string.IsNullOrWhiteSpace(logEntry.IpAddress));
    }
    
    [Fact]
    public async Task Logout_ValidRequest_ReturnsSuccess()
    {
        var requestBody = new
        {
            userName = "LoggedInUser2",
            password = "Password123!",
        };

        var loginResponse = await Client.PostAsJsonAsync("/auth/login", requestBody);
        Assert.Equal(HttpStatusCode.Unauthorized, loginResponse.StatusCode);
        var loginResponseData = await loginResponse.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();
        Assert.NotNull(loginResponseData);
        Assert.NotNull(loginResponseData.Data!.Token);

        var token = loginResponseData.Data.Token;
        var logoutRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/logout");

        Factory.CreateClient();
        using var scope = Factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var userId = (await userManager.FindByNameAsync("LoggedInUser2"))!.Id;

        logoutRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        logoutRequest.Content = JsonContent.Create(new { UserId = userId, Token = token });
        var logoutResponse = await Client.SendAsync(logoutRequest);

        Assert.Equal(HttpStatusCode.OK, logoutResponse.StatusCode);
        var logoutResponseData = await logoutResponse.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();
        Assert.NotNull(logoutResponseData);
        Assert.True(logoutResponseData.Success);
        Assert.Equal("Logged out successfully.", logoutResponseData.Message);
        Assert.Equal(OperationStatus.Ok, logoutResponseData.Data!.Status);
        Assert.Equal("The user has been logged out successfully.", logoutResponseData.Data.Description);
    }

    [Fact]
    public async Task Logout_InvalidRequest_ReturnsUnauthorized()
    {
        var fakeToken = "InvalidTokenString";

        var request = new HttpRequestMessage(HttpMethod.Post, "/auth/logout");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", fakeToken);
        request.Content = JsonContent.Create(new { });

        var response = await Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var responseData = await response.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();
        Assert.NotNull(responseData);
        Assert.False(responseData.Success);
        Assert.Equal("Invalid request. Please provide a valid token.", responseData.Message);
        Assert.Equal(OperationStatus.Failed, responseData.Error!.Status);
        Assert.Equal("Authentication failed.", responseData.Error.Description);
        Assert.Equal("INVALID_REQUEST", responseData.Error.Code);
        Assert.Contains("Invalid request. Please provide a valid token.", responseData.Error!.Errors!);

        Assert.Equal(ErrorCategory.Authentication, responseData.Error!.Category);
    }

    [Fact]
    public async Task Logout_RevokesRefreshToken()
    {
        using var scope = Factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var refreshService = scope.ServiceProvider.GetRequiredService<IRefreshTokenService>();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        // Step 1: Create refresh token
        var user = await userManager.FindByNameAsync("TestUserNo2FA");
        var refreshResult = await refreshService.CreateRefreshTokenAsync(user!);
        var refreshToken = refreshResult.Data!.Token;

        // Step 2: Log the user in
        var client = CreateClientWithCookies(out _);
        var loginResponse = await client.PostAsJsonAsync("/auth/login", new
        {
            userName = "TestUserNo2FA",
            password = "Password123!",
            rememberMe = false
        });

        var loginContent = await loginResponse.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();
        Assert.NotNull(loginContent);
        Assert.True(loginContent!.Success);

        var jwtToken = loginContent.Data!.Token;
        Output.WriteLine($"Refresh token used: {refreshToken}");

        // Step 3: Send logout with refresh token
        var logoutRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/logout");
        logoutRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", jwtToken);
        logoutRequest.Content = JsonContent.Create(new
        {
            UserId = user.Id,
            Token = refreshToken
        });

        var logoutResponse = await client.SendAsync(logoutRequest);
        Assert.Equal(HttpStatusCode.OK, logoutResponse.StatusCode);

        // Step 4: Verify that the token was revoked
        var storedToken = await db.RefreshTokens.FirstOrDefaultAsync(t => t.Token == refreshToken);
        // Force refresh from DB to get the latest state
        await db.Entry(storedToken!).ReloadAsync();
        Assert.NotNull(storedToken);
        Assert.True(storedToken!.IsRevoked);
    }


    private HttpClient CreateClientWithCookies(out CookieContainer cookieContainer)
    {
        cookieContainer = new CookieContainer();

        var httpClientHandler = new HttpClientHandler
        {
            UseCookies = true,
            CookieContainer = cookieContainer,
            AllowAutoRedirect = false
        };

        var delegatingHandler = new CookiePassthroughHandler(httpClientHandler);

        var client = Factory.CreateDefaultClient(delegatingHandler);
        client.BaseAddress = new Uri("http://localhost");

        return client;
    }

    private class CookiePassthroughHandler : DelegatingHandler
    {
        public CookiePassthroughHandler(HttpMessageHandler innerHandler)
        {
            InnerHandler = innerHandler ?? throw new ArgumentNullException(nameof(innerHandler));
        }
    }
}