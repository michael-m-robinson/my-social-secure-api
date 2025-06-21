using System.Net;
using System.Net.Http.Json;
using System.Runtime.InteropServices.JavaScript;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using My_Social_Secure_Api.Enums.Common;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Common;
using My_Social_Secure_Api.Models.Dtos.Registration;
using My_Social_Secure_Api.Models.Identity;
using Social_Secure_Integration_Tests.Infrastructure;
using Social_Secure_Integration_Tests.Utilities;

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
            userName = "testuser",
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

        Assert.Equal(System.Net.HttpStatusCode.BadRequest, response.StatusCode);

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

        Assert.Equal(System.Net.HttpStatusCode.BadRequest, response.StatusCode);

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
    public async Task Register_EmailAlreadyExists_ReturnsBadRequest()
    {
        var requestBody = new
        {
            userName = "testuser",
            email = "existing@user.com",
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
        Assert.Equal(System.Net.HttpStatusCode.BadRequest, response.StatusCode);

        var responseData = await response.Content.ReadFromJsonAsync<ApiResponse<RegisterDto>>();
        Assert.NotNull(responseData);
        Assert.False(responseData.Success);
        Assert.Equal(OperationStatus.Failed, responseData!.Error!.Status);
        Assert.Equal(ErrorCategory.Authentication, responseData!.Error!.Category);
        Assert.Equal("Authentication failed.", responseData.Error.Description);
        Assert.Equal("AUTH_FAILURE", responseData.Error.Code);
        Assert.Contains("Email is already in use.", responseData.Error!.Errors!);
    }
    
    [Fact]
    public async Task Register_UsernameAlreadyExists_ReturnsBadRequest()
    {
        var requestBody = new
        {
            userName = "existingEmailUser",
            email = "test@user.com",
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
        Assert.Equal(System.Net.HttpStatusCode.BadRequest, response.StatusCode);
        
        var responseData = await response.Content.ReadFromJsonAsync<ApiResponse<RegisterDto>>();
        Assert.NotNull(responseData);
        Assert.False(responseData.Success);
        Assert.Equal(OperationStatus.Failed, responseData!.Error!.Status);
        Assert.Equal(ErrorCategory.Authentication, responseData!.Error!.Category);
        Assert.Equal("Authentication failed.", responseData.Error.Description);
        Assert.Equal("AUTH_FAILURE", responseData.Error.Code);
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
        Assert.Equal(System.Net.HttpStatusCode.BadRequest, response.StatusCode);
        
        var responseData = await response.Content.ReadFromJsonAsync<ApiResponse<RegisterDto>>();
        Assert.NotNull(responseData);
        Assert.False(responseData.Success);
        Assert.Equal(OperationStatus.Failed, responseData!.Error!.Status);
        Assert.Equal(ErrorCategory.Authentication, responseData!.Error!.Category);
        Assert.Equal("Authentication failed.", responseData.Error.Description);
        Assert.Equal("AUTH_FAILURE", responseData.Error.Code);
        Assert.Contains("Password and confirm password do not match.", responseData.Error!.Errors!);
    }
    
    [Fact]
    public async Task Login_ValidCredentials_ReturnsSuccess()
    {
        var requestBody = new
        {
            userName = "LoggedInUser1",
            password = "Password123!",
        };

        var request = new
        {
            Url = "/auth/login",
            Body = requestBody
        };

        var response = await Client.PostAsJsonAsync(request.Url, request.Body);
        
        Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
        
        var responseData = await response.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();
        Assert.NotNull(responseData);
        Assert.NotNull(responseData.Data!.Token);
        Assert.Equal("The user was successfully authenticated.", responseData.Data!.Description);
        Assert.Equal(OperationStatus.Ok, responseData.Data.Status);
        Assert.Equal("Login successful.", responseData.Message);
        Assert.True(responseData.Success);
    }
    
    [Fact]
    public async Task Login_EmptyCredentials_ReturnsBadRequest()
    {
        var requestBody = new
        {
            userName = "",
            password = "",
        };

        var request = new
        {
            Url = "/auth/login",
            Body = requestBody
        };

        var response = await Client.PostAsJsonAsync(request.Url, request.Body);
        
        Assert.Equal(System.Net.HttpStatusCode.BadRequest, response.StatusCode);
        
        var errors = await response.Content.ReadFromJsonAsync<ValidationProblemDetails>();
        Assert.NotNull(errors);
        Assert.Contains("UserName", errors!.Errors.Keys);
        Assert.Contains("Password", errors.Errors.Keys);
    }
    
    [Fact]
    public async Task Login_InvalidUsername_ReturnsUnauthorized()
    {
        var requestBody = new
        {
            userName = "InvalidUser",
            password = "WrongPassword",
        };

        var request = new
        {
            Url = "/auth/login",
            Body = requestBody
        };

        var response = await Client.PostAsJsonAsync(request.Url, request.Body);
        
        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, response.StatusCode);
        
        var responseData = await response.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();
        Assert.NotNull(responseData);
        Assert.False(responseData.Success);
        Assert.Equal(OperationStatus.Error, responseData.Error!.Status);
        Assert.Equal(ErrorCategory.NotFound, responseData.Error.Category);
        Assert.Equal("The resource you're trying to access was not found.", responseData.Error.Description);
        Assert.Equal("User not found.", responseData.Message);
        Assert.Equal("NOT_FOUND", responseData.Error.Code);
    }
    
    [Fact]
    public async Task Login_InvalidPassword_ReturnsUnauthorized()
    {
        var requestBody = new
        {
            userName = "LoggedInUser1",
            password = "WrongPassword",
        };

        var request = new
        {
            Url = "/auth/login",
            Body = requestBody
        };

        var response = await Client.PostAsJsonAsync(request.Url, request.Body);
        
        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, response.StatusCode);
        
        var responseData = await response.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();
        Assert.NotNull(responseData);
        Assert.False(responseData.Success);
        Assert.Equal(OperationStatus.Error, responseData.Error!.Status);
        Assert.Equal(ErrorCategory.Validation, responseData.Error.Category);
        Assert.Equal("Some fields contain invalid or missing values.", responseData.Error.Description);
        Assert.Equal("Incorrect password.", responseData.Message);
        Assert.Equal("VALIDATION_ERROR", responseData.Error.Code);
    }

    [Fact]
    public async Task Login_TwoFactorRequired_ReturnsSuccess()
    {
        var requestBody = new
        {
            userName = "LoggedInUser2",
            password = "Password123!",
        };

        var request = new
        {
            Url = "/auth/login",
            Body = requestBody
        };
        
        // 1️⃣ First login submission
        var response = await Client.PostAsJsonAsync(request.Url, request.Body);
        var responseContent = await response.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();
        Assert.Equal("REQUIRES_2FA", responseContent!.Error!.Code);
        
        var partialToken = responseContent.Data!.Token;
        
        // 2️⃣ Retrieve user and generate the 2FA token inside test
        using var scope = factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await userManager.FindByNameAsync(requestBody.userName);
        var twoFaCode = await userManager.GenerateTwoFactorTokenAsync(user!, "Email");
        
        // 3️⃣ Submit 2FA code
        var verifyRequestBody = new { UserName = requestBody.userName, Token = partialToken, Code = twoFaCode, RememberMe = false };
        var verifyResponse = await Client.PostAsJsonAsync("/auth/login-2fa", verifyRequestBody);
        Assert.Equal(HttpStatusCode.OK, verifyResponse.StatusCode);
        
        var verifyResponseData = await verifyResponse.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();
        Assert.NotNull(verifyResponseData);
        Assert.True(verifyResponseData!.Success);
        Assert.Equal("Login successful.", verifyResponseData.Message);
        Assert.Equal(OperationStatus.Ok, verifyResponseData.Data!.Status);
        Assert.NotNull(verifyResponseData.Data!.Token);
        Assert.Equal("The user was successfully authenticated.", verifyResponseData.Data.Description);
    }

    [Fact]
    public async Task Login_TwoFactorInvalidCode_ReturnsUnauthorized()
    {
        var requestBody = new
        {
            userName = "LoggedInUser2",
            password = "Password123!",
        };

        var request = new
        {
            Url = "/auth/login",
            Body = requestBody
        };

        // 1️⃣ First login submission
        var response = await Client.PostAsJsonAsync(request.Url, request.Body);
        var responseContent = await response.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();
        Assert.Equal("REQUIRES_2FA", responseContent!.Error!.Code);
        var partialToken = responseContent.Data!.Token;

        // 2️⃣ Submit invalid 2FA code
        var verifyRequestBody = new
        {
            UserName = requestBody.userName,
            Token = partialToken,
            Code = "Invalid2FACode",
            RememberMe = false
        };

        var verifyResponse = await Client.PostAsJsonAsync("/auth/login-2fa", verifyRequestBody);
        Assert.Equal(HttpStatusCode.Unauthorized, verifyResponse.StatusCode);

        var verifyResponseData = await verifyResponse.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();
        Assert.NotNull(verifyResponseData);
        Assert.False(verifyResponseData!.Success);
        Assert.Equal(OperationStatus.Failed, verifyResponseData.Error!.Status);
        Assert.Equal(ErrorCategory.Authentication, verifyResponseData.Error.Category);
        Assert.Equal("Authentication failed.", verifyResponseData.Error.Description);
        Assert.Equal("AUTH_FAILURE", verifyResponseData.Error.Code);
        Assert.Equal("Authentication failed.", verifyResponseData.Error.Description);
        Assert.Contains("Invalid 2FA code.", verifyResponseData.Message);
    }
}
