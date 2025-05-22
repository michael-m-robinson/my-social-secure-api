using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Moq;

namespace My_Social_Secure_Api_Tests.Shared;

public abstract class TestBase
{
    protected readonly Mock<ILoggerFactory> LoggerFactoryMock = new();
    protected readonly Mock<IHttpContextAccessor> HttpContextAccessorMock = new();

    protected Mock<UserManager<TUser>> GetUserManagerMock<TUser>() where TUser : class
    {
        var store = new Mock<IUserStore<TUser>>();
        return new Mock<UserManager<TUser>>(store.Object, null!, null!, null!, null!, null!, null!, null!, null!);
    }

    protected ClaimsPrincipal CreateClaimsPrincipal(string userId)
    {
        var claims = new[] { new Claim(ClaimTypes.NameIdentifier, userId) };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        return new ClaimsPrincipal(identity);
    }
}