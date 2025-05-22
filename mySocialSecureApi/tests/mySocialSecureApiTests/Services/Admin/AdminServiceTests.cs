using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using My_Social_Secure_Api.Data;
using My_Social_Secure_Api.Models.Identity;
using My_Social_Secure_Api.Services.Admin;
using Microsoft.AspNetCore.Identity;
using My_Social_Secure_Api.Interfaces.Services.DeviceRecognition;
using My_Social_Secure_Api.Models.Dtos.Admin;
using My_Social_Secure_Api.Models.Entities.Auth;

public class AdminServiceTests
{
    private readonly ApplicationDbContext _dbContext;
    private readonly Mock<UserManager<ApplicationUser>> _mockUserManager;
    private readonly AdminService _service;

    public AdminServiceTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        _dbContext = new ApplicationDbContext(options);
        var mockLogger = new Mock<ILogger<AdminService>>();
        var mockHttpContextAccessor = new Mock<IHttpContextAccessor>();

        var userStore = new Mock<IUserStore<ApplicationUser>>();
        _mockUserManager = new Mock<UserManager<ApplicationUser>>(
            userStore.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        var mockDeviceRecognition = new Mock<IDeviceRecognitionService>();

        var httpContext = new DefaultHttpContext
        {
            Items =
            {
                ["X-Correlation-ID"] = "test-correlation-id"
            }
        };
        mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(httpContext);

        _service = new AdminService(
            _dbContext,
            _mockUserManager.Object,
            mockLogger.Object,
            mockDeviceRecognition.Object,
            mockHttpContextAccessor.Object);
    }

    [Fact]
    public async Task GetAllUsersAsync_ReturnsAllUsers()
    {
        _dbContext.Users.AddRange(
            new ApplicationUser
            {
                Id = "1",
                Email = "a@example.com",
                UserName = "userA",
                FirstName = "Alice",
                LastName = "Smith",
                City = "New York",
                State = "NY",
            },
            new ApplicationUser
            {
                Id = "2",
                Email = "b@example.com",
                UserName = "userB",
                FirstName = "Bob",
                LastName = "Johnson",
                City = "Los Angeles",
                State = "CA",
            }
        );
        await _dbContext.SaveChangesAsync();

        var result = await _service.GetAllUsersAsync();

        Assert.True(result.Success);
        Assert.Equal("Users fetched successfully.", result.Message);
        Assert.NotNull(result.Data);
        Assert.Equal(2, result.Data.Users.Count);
        Assert.Equal("a@example.com", result.Data.Users[0].Email);
    }

    [Fact]
    public async Task GetUserByIdAsync_ReturnsCorrectUser()
    {
        var user = new ApplicationUser
        {
            Id = "u1",
            Email = "user@example.com",
            UserName = "test-user",
            FirstName = "Test",
            LastName = "User",
            City = "Test City",
            State = "Test State",
        };
        _dbContext.Users.Add(user);
        await _dbContext.SaveChangesAsync();

        var result = await _service.GetUserByIdAsync("u1");

        Assert.True(result.Success);
        Assert.Equal("User fetched successfully.", result.Message);
        Assert.NotNull(result.Data);
        Assert.Equal("u1", result.Data.UserId);
        Assert.Equal("user@example.com", result.Data.Email);
    }

    [Fact]
    public async Task GetUserByIdAsync_ReturnsNotFound_WhenUserDoesNotExist()
    {
        var result = await _service.GetUserByIdAsync("nonexistent-id");

        Assert.False(result.Success);
        Assert.Equal("User not found.", result.Message);
        Assert.Null(result.Data);
    }

    [Fact]
    public async Task UpdateUserAsync_UpdatesFields_WhenUserExists()
    {
        var user = new ApplicationUser
        {
            Id = "u1",
            Email = "old@example.com",
            UserName = "old-user",
            FirstName = "Old",
            LastName = "Name",
            City = "Old City",
            State = "Old State",
        };

        _mockUserManager.Setup(x => x.FindByIdAsync("u1")).ReturnsAsync(user);
        _mockUserManager.Setup(x => x.UpdateAsync(It.IsAny<ApplicationUser>())).ReturnsAsync(IdentityResult.Success);

        var dto = new UpdateUserDto
        {
            Email = "new@example.com",
            UserName = "new-user",
            FirstName = "New",
            LastName = "Name"
        };

        var result = await _service.UpdateUserAsync("u1", dto);

        Assert.True(result.Success);
        Assert.Equal("User updated successfully.", result.Message);
        Assert.NotNull(result.Data);
        Assert.Equal("new@example.com", result.Data.Email);
        Assert.Equal("new-user", result.Data.UserName);
    }

    [Fact]
    public async Task UpdateUserAsync_ReturnsNotFound_WhenUserDoesNotExist()
    {
        _mockUserManager.Setup(x => x.FindByIdAsync("u2")).ReturnsAsync((ApplicationUser)null!);

        var dto = new UpdateUserDto { Email = "x@x.com", UserName = "x", FirstName = "x", LastName = "x" };

        var result = await _service.UpdateUserAsync("u2", dto);

        Assert.False(result.Success);
        Assert.Equal("User not found.", result.Message);
        Assert.Null(result.Data);
    }

    [Fact]
    public async Task UpdateUserAsync_ReturnsError_WhenUpdateFails()
    {
        var user = new ApplicationUser
        {
            Id = "u3",
            Email = "a@a.com",
            FirstName = "John",
            LastName = "Smith",
            City = "New York",
            State = "NY",
        };
        _mockUserManager.Setup(x => x.FindByIdAsync("u3")).ReturnsAsync(user);
        _mockUserManager.Setup(x => x.UpdateAsync(It.IsAny<ApplicationUser>())).ReturnsAsync(IdentityResult.Failed());

        var dto = new UpdateUserDto { Email = "x@x.com", UserName = "x", FirstName = "x", LastName = "x" };

        var result = await _service.UpdateUserAsync("u3", dto);

        Assert.False(result.Success);
        Assert.Equal("Failed to update the user.", result.Message);
    }
    
    [Fact]
    public async Task AssignRoleAsync_AddsRoleSuccessfully()
    {
        var user = new ApplicationUser
        {
            Id = "u1",
            Email = "a@a.com",
            FirstName = "John",
            LastName = "Smith",
            City = "New York",
            State = "NY",
        };
        _mockUserManager.Setup(m => m.FindByIdAsync("u1")).ReturnsAsync(user);
        _mockUserManager.Setup(m => m.AddToRoleAsync(user, "Admin")).ReturnsAsync(IdentityResult.Success);

        var dto = new RoleAssignmentRequestDto { UserId = "u1", RoleName = "Admin" };

        var result = await _service.AssignRoleAsync(dto);

        Assert.True(result.Success);
        Assert.Equal("Role assigned successfully.", result.Message);
    }

    [Fact]
    public async Task AssignRoleAsync_ReturnsNotFound_WhenUserDoesNotExist()
    {
        _mockUserManager.Setup(m => m.FindByIdAsync("missing")).ReturnsAsync((ApplicationUser)null!);

        var dto = new RoleAssignmentRequestDto { UserId = "missing", RoleName = "Admin" };

        var result = await _service.AssignRoleAsync(dto);

        Assert.False(result.Success);
        Assert.Equal("User not found.", result.Message);
    }

    [Fact]
    public async Task AssignRoleAsync_ReturnsError_WhenAssignmentFails()
    {
        var user = new ApplicationUser
        {
            Id = "u2",
            Email = "b@b.com",
            FirstName = "Jane",
            LastName = "Doe",
            City = "Los Angeles",
            State = "CA",
        };
        _mockUserManager.Setup(m => m.FindByIdAsync("u2")).ReturnsAsync(user);
        _mockUserManager.Setup(m => m.AddToRoleAsync(user, "Admin"))
            .ReturnsAsync(IdentityResult.Failed());

        var dto = new RoleAssignmentRequestDto { UserId = "u2", RoleName = "Admin" };

        var result = await _service.AssignRoleAsync(dto);

        Assert.False(result.Success);
        Assert.Equal("Failed to assign the role.", result.Message);
    }
    
    [Fact]
    public async Task RemoveRoleAsync_RemovesRoleSuccessfully()
    {
        var user = new ApplicationUser
        {
            Id = "u3",
            Email = "c@c.com",
            FirstName = "Jack",
            LastName = "Brown",
            City = "Chicago",
            State = "IL",
        };
        _mockUserManager.Setup(m => m.FindByIdAsync("u3")).ReturnsAsync(user);
        _mockUserManager.Setup(m => m.RemoveFromRoleAsync(user, "Admin"))
            .ReturnsAsync(IdentityResult.Success);

        var dto = new RoleRemovalRequestDto { UserId = "u3", RoleName = "Admin" };

        var result = await _service.RemoveRoleAsync(dto);

        Assert.True(result.Success);
        Assert.Equal("Role removed successfully.", result.Message);
    }

    [Fact]
    public async Task RemoveRoleAsync_ReturnsNotFound_WhenUserDoesNotExist()
    {
        _mockUserManager.Setup(m => m.FindByIdAsync("not-found")).ReturnsAsync((ApplicationUser)null!);

        var dto = new RoleRemovalRequestDto { UserId = "not-found", RoleName = "Admin" };

        var result = await _service.RemoveRoleAsync(dto);

        Assert.False(result.Success);
        Assert.Equal("User not found.", result.Message);
    }

    [Fact]
    public async Task RemoveRoleAsync_ReturnsError_WhenRemovalFails()
    {
        var user = new ApplicationUser
        {
            Id = "u4",
            Email = "d@d.com",
            FirstName = "Emily",
            LastName = "White",
            City = "Miami",
            State = "FL",
        };
        _mockUserManager.Setup(m => m.FindByIdAsync("u4")).ReturnsAsync(user);
        _mockUserManager.Setup(m => m.RemoveFromRoleAsync(user, "Admin"))
            .ReturnsAsync(IdentityResult.Failed());

        var dto = new RoleRemovalRequestDto { UserId = "u4", RoleName = "Admin" };

        var result = await _service.RemoveRoleAsync(dto);

        Assert.False(result.Success);
        Assert.Equal("Failed to remove the role.", result.Message);
    }
    
    [Fact]
    public async Task GetUserRolesAsync_ReturnsRoleList_WhenUserExists()
    {
        var user = new ApplicationUser
        {
            Id = "u5",
            Email = "e@e.com",
            FirstName = "Michael",
            LastName = "Green",
            City = "Seattle",
            State = "WA",
        };
        var roles = new List<string> { "Admin", "User" };

        _mockUserManager.Setup(m => m.FindByIdAsync("u5")).ReturnsAsync(user);
        _mockUserManager.Setup(m => m.GetRolesAsync(user)).ReturnsAsync(roles);

        var result = await _service.GetUserRolesAsync("u5");

        Assert.True(result.Success);
        Assert.Equal("User roles fetched successfully.", result.Message);
        Assert.NotNull(result.Data);
        Assert.Equal(2, result.Data.Roles.Count);
        Assert.Contains("Admin", result.Data.Roles);
    }

    [Fact]
    public async Task GetUserRolesAsync_ReturnsNotFound_WhenUserMissing()
    {
        _mockUserManager.Setup(m => m.FindByIdAsync("none")).ReturnsAsync((ApplicationUser)null!);

        var result = await _service.GetUserRolesAsync("none");

        Assert.False(result.Success);
        Assert.Equal("User not found.", result.Message);
        Assert.Null(result.Data);
    }
    
    [Fact]
    public async Task GetUserLoginHistoryAsync_ReturnsHistory_WhenAvailable()
    {
        _dbContext.LoginHistories.AddRange(new[]
        {
            new LoginHistoryModel() { UserId = "u6", Device = "Chrome", IpAddress = "1.2.3.4" },
            new LoginHistoryModel { UserId = "u6", Device = "Firefox", IpAddress = "5.6.7.8" }
        });
        await _dbContext.SaveChangesAsync();

        var result = await _service.GetUserLoginHistoryAsync("u6");

        Assert.True(result.Success);
        Assert.Equal("Login history fetched successfully.", result.Message);
        Assert.NotNull(result.Data);
        Assert.Equal(2, result.Data.LoginHistories.Count);
    }

    [Fact]
    public async Task GetUserLoginHistoryAsync_ReturnsEmpty_WhenNoHistoryExists()
    {
        var result = await _service.GetUserLoginHistoryAsync("none");

        Assert.True(result.Success);
        Assert.Empty(result.Data!.LoginHistories);
    }
    
    [Fact]
    public async Task GetTopTenUserLoginAlertsAsync_ReturnsAlerts_WhenAvailable()
    {
        _dbContext.LoginAlerts.AddRange(new[]
        {
            new LoginAlertModel { UserId = "u7", Location = "USA" },
            new LoginAlertModel { UserId = "u7", Location = "Canada" }
        });
        await _dbContext.SaveChangesAsync();

        var result = await _service.GetTopTenUserLoginAlertsAsync("u7");

        Assert.True(result.Success);
        Assert.Equal("Top 10 login alerts fetched successfully.", result.Message);
        Assert.NotNull(result.Data);
        Assert.Equal(2, result.Data.LoginAlerts.Count);
    }

    [Fact]
    public async Task GetTopTenUserLoginAlertsAsync_ReturnsEmpty_WhenNoAlertsExist()
    {
        var result = await _service.GetTopTenUserLoginAlertsAsync("no-user");

        Assert.True(result.Success);
        Assert.Empty(result.Data!.LoginAlerts);
    }
}
