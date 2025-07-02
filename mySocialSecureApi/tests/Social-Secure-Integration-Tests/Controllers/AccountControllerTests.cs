using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using My_Social_Secure_Api.Interfaces.Services.Auth;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Account;
using My_Social_Secure_Api.Models.Dtos.Admin;
using My_Social_Secure_Api.Models.Dtos.Common;
using My_Social_Secure_Api.Models.Identity;
using Social_Secure_Integration_Tests.Infrastructure;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using Xunit.Abstractions;

namespace Social_Secure_Integration_Tests.Controllers;

public class AccountControllerTests(CustomWebApplicationFactory factory, ITestOutputHelper output)
    : IntegrationTestBase(factory, output)
{
    [Fact]
    public async Task GetProfile_SeededUserNo2FA_ReturnsProfileData()
    {
        Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("JWT_SECRET_KEY") ?? "TestSecretKey_123!");

        // Arrange
        using var scope = Factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var jwtGenerator = scope.ServiceProvider.GetRequiredService<IJwtTokenGenerator>();

        var user = await userManager.FindByEmailAsync("no2fa@example.com");
        Assert.NotNull(user);
        Assert.True(user.EmailConfirmed);

        // Ensure role
        const string role = "User";
        if (!await userManager.IsInRoleAsync(user, role))
            await userManager.AddToRoleAsync(user, role);

        var extraClaims = new List<Claim>
        {
            new("Permission", "CanViewOwnProfile")
        };

        // Ensure permission claim exists
        var existingClaims = await userManager.GetClaimsAsync(user);
        if (!existingClaims.Any(c => c.Type == "Permission" && c.Value == "CanViewOwnProfile"))
        {
            await userManager.AddClaimAsync(user, new Claim("Permission", "CanViewOwnProfile"));
        }

        // Generate token
        var token = await jwtGenerator.GenerateToken(user);
        Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // Act
        var response = await Client.GetAsync("/account/profile");

        // Assert
        response.EnsureSuccessStatusCode();
        var result = await response.Content.ReadFromJsonAsync<ApiResponse<UserProfileDto>>();

        Assert.NotNull(result);
        Assert.True(result!.Success);
        Assert.Equal(user.UserName, result.Data!.Username);
        Assert.Equal(user.Email, result.Data.Email);
        Assert.Equal(user.FirstName, result.Data.FirstName);
        Assert.Equal(user.LastName, result.Data.LastName);
        Assert.Equal(user.Id, result.Data.Id);
    }
}