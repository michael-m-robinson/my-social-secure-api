using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Runtime.InteropServices.JavaScript;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using My_Social_Secure_Api.Enums.Common;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Common;
using My_Social_Secure_Api.Models.Dtos.Registration;
using My_Social_Secure_Api.Models.Identity;
using OtpNet;
using Social_Secure_Integration_Tests.Infrastructure;


namespace Social_Secure_Integration_Tests.Controllers;

// File: AuthControllerTests.cs
public class AuthControllerTests(CustomWebApplicationFactory factory) : IntegrationTestBase(factory)
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

    // ToDo: LoginWith2Fa_ValidCode_ReturnsSuccess()

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