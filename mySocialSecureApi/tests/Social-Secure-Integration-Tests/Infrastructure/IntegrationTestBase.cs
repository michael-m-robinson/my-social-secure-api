using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;
using My_Social_Secure_Api.Models.Identity;
using Microsoft.AspNetCore.Identity;

namespace Social_Secure_Integration_Tests.Infrastructure;

public abstract class IntegrationTestBase : IClassFixture<CustomWebApplicationFactory>
{
    protected readonly HttpClient Client;
    protected readonly CustomWebApplicationFactory Factory;
    protected readonly ITestOutputHelper Output;

    protected IntegrationTestBase(CustomWebApplicationFactory factory, ITestOutputHelper output)
    {
        Factory = factory;
        Output = output;
        Client = factory.CreateClient();

        using var scope = Factory.Services.CreateScope();
        var serviceProvider = scope.ServiceProvider;
        AssignTestUsersToRolesAsync(serviceProvider).GetAwaiter().GetResult();
    }

    private static async Task AssignTestUsersToRolesAsync(IServiceProvider serviceProvider)
    {
        var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();

        var user = await userManager.FindByNameAsync("TestUserNo2FA");
        if (user is not null && !(await userManager.IsInRoleAsync(user, "User")))
        {
            await userManager.AddToRoleAsync(user, "User");
        }
    }
}