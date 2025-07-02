using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Admin;
using My_Social_Secure_Api.Models.Dtos.Common;
using My_Social_Secure_Api.Models.Dtos.LoginTracking;
using My_Social_Secure_Api.Models.Dtos.Notifications;
using My_Social_Secure_Api.Models.Identity;
using Social_Secure_Integration_Tests.Infrastructure;
using System.Net.Http.Json;
using Xunit.Abstractions;


namespace Social_Secure_Integration_Tests.Controllers;

public class AdminControllerTests(CustomWebApplicationFactory factory, ITestOutputHelper output)
    : IntegrationTestBase(factory, output)
{
    [Fact]
    public async Task GetAllUsers_ReturnsUserList()
    {
        var response = await Client.GetAsync("/admin/users");
        response.EnsureSuccessStatusCode();
        var result = await response.Content.ReadFromJsonAsync<ApiResponse<UserListDto>>();

        Assert.NotNull(result);
        Assert.True(result!.Success);
        Assert.NotEmpty(result.Data!.Users);
    }

    [Fact]
    public async Task GetUserById_ValidUser_ReturnsUserDetails()
    {
        using var scope = Factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await userManager.FindByNameAsync("TestUserNo2FA");

        var response = await Client.GetAsync($"/admin/users/{user!.Id}");
        var result = await response.Content.ReadFromJsonAsync<ApiResponse<UserActionDto>>();

        Assert.True(result!.Success);
        Assert.Equal(user.Email, result.Data!.Email);
    }

    [Fact]
    public async Task GetUserById_Nonexistent_ReturnsNotFound()
    {
        var response = await Client.GetAsync("/admin/users/invalid-user-id");
        var result = await response.Content.ReadFromJsonAsync<ApiResponse<UserActionDto>>();

        Assert.False(result!.Success);
        Assert.Equal("NOT_FOUND", result.Error!.Code);
    }

    [Fact]
    public async Task UpdateUser_ValidData_UpdatesSuccessfully()
    {
        using var scope = Factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await userManager.FindByNameAsync("TestUserNo2FA");

        var dto = new UpdateUserDto
        {
            Email = "updated@example.com",
            UserName = "UpdatedUser",
            FirstName = "Updated",
            LastName = "Name"
        };

        var response = await Client.PutAsJsonAsync($"/admin/users/{user!.Id}", dto);
        var result = await response.Content.ReadFromJsonAsync<ApiResponse<UserActionDto>>();

        Assert.True(result!.Success);
        Assert.Equal(dto.Email, result.Data!.Email);
    }

    [Fact]
    public async Task AssignRole_ValidInput_AssignsRole()
    {
        using var scope = Factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        var user = await userManager.FindByNameAsync("TestUserNo2FA");
        var role = "TestRole";

        if (!await roleManager.RoleExistsAsync(role))
            await roleManager.CreateAsync(new IdentityRole(role));

        var response = await Client.PostAsync($"/admin/users/{user!.Id}/roles?role={role}", null);
        var result = await response.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();

        Assert.True(result!.Success);
    }

    [Fact]
    public async Task RemoveRole_ValidInput_RemovesRole()
    {
        using var scope = Factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        var user = await userManager.FindByNameAsync("TestUserNo2FA");
        var role = "TestRole";

        if (!await roleManager.RoleExistsAsync(role))
            await roleManager.CreateAsync(new IdentityRole(role));

        await userManager.AddToRoleAsync(user!, role);

        var response = await Client.DeleteAsync($"/admin/users/{user.Id}/roles?role={role}");
        var result = await response.Content.ReadFromJsonAsync<ApiResponse<OperationDto>>();

        Assert.True(result!.Success);
    }

    [Fact]
    public async Task GetUserRoles_ReturnsRoles()
    {
        using var scope = Factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        var user = await userManager.FindByNameAsync("TestUserNo2FA");
        var role = "RoleCheck";

        if (!await roleManager.RoleExistsAsync(role))
            await roleManager.CreateAsync(new IdentityRole(role));

        await userManager.AddToRoleAsync(user!, role);

        var response = await Client.GetAsync($"/admin/users/{user.Id}/roles");
        var result = await response.Content.ReadFromJsonAsync<ApiResponse<RoleListDto>>();

        Assert.True(result!.Success);
        Assert.Contains(role, result.Data!.Roles);
    }

    [Fact]
    public async Task GetUserLoginHistory_ReturnsHistory()
    {
        using var scope = Factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await userManager.FindByNameAsync("TestUserNo2FA");

        var response = await Client.GetAsync($"/admin/users/{user!.Id}/login-history");
        var result = await response.Content.ReadFromJsonAsync<ApiResponse<LoginHistoryListDto>>();

        Assert.True(result!.Success);
    }

    [Fact]
    public async Task GetTopTenLoginAlerts_ReturnsAlerts()
    {
        using var scope = Factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await userManager.FindByNameAsync("TestUserNo2FA");

        var response = await Client.GetAsync($"/admin/users/{user!.Id}/top-login-alerts");
        var result = await response.Content.ReadFromJsonAsync<ApiResponse<LoginAlertListDto>>();

        Assert.True(result!.Success);
    }
}