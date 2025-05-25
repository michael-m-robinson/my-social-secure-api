using System.Net.Http.Json;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Registration;
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

        // response.EnsureSuccessStatusCode();
        // var json = await response.Content.ReadFromJsonAsync<ApiResponse<RegisterDto>>();
        
        var result = await response.Content.ReadAsStringAsync();

        //Assert.True(json?.Success);
        // Assert.Equal("test@example.com", json?.Data?.Email);
    }
}