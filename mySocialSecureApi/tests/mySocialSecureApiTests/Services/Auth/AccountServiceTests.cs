using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using My_Social_Secure_Api.Models.Identity;
using My_Social_Secure_Api.Models.Dtos.Account;
using My_Social_Secure_Api.Interfaces.Services.Notifications;
using My_Social_Secure_Api.Interfaces.Services.Utilities;
using My_Social_Secure_Api.Enums.Common;
using My_Social_Secure_Api.Models.Account;
using My_Social_Secure_Api.Services.Auth;

public class AccountServiceTests
{
    private readonly Mock<UserManager<ApplicationUser>> _mockUserManager;
    private readonly Mock<IUrlBuilderService> _mockUrlBuilderService;
    private readonly AccountService _service;

    public AccountServiceTests()
    {
        var store = new Mock<IUserStore<ApplicationUser>>();
        _mockUserManager =
            new Mock<UserManager<ApplicationUser>>(store.Object, null!, null!, null!, null!, null!, null!, null!,
                null!);
        var mockLogger = new Mock<ILogger<AccountService>>();
        var mockHttpContextAccessor = new Mock<IHttpContextAccessor>();
        var mockUserEmailService = new Mock<IUserEmailService>();
        _mockUrlBuilderService = new Mock<IUrlBuilderService>();

        var context = new DefaultHttpContext
        {
            Items =
            {
                ["X-Correlation-ID"] = "test-correlation-id"
            }
        };
        mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(context);

        _service = new AccountService(
            mockLogger.Object,
            _mockUserManager.Object,
            mockUserEmailService.Object,
            _mockUrlBuilderService.Object,
            mockHttpContextAccessor.Object);
    }

    [Fact]
    public async Task GetUserProfileAsync_ReturnsSuccess_WhenUserExists()
    {
        var user = new ApplicationUser
        {
            Id = "1",
            Email = "test@example.com",
            UserName = "test-user",
            FirstName = "Test",
            LastName = "User",
            PhoneNumber = "1234567890",
            City = "Test City",
            State = "Test State",
        };

        _mockUserManager.Setup(m => m.FindByIdAsync("1")).ReturnsAsync(user);
        _mockUserManager.Setup(m => m.IsLockedOutAsync(user)).ReturnsAsync(false);

        var result = await _service.GetUserProfileAsync("1");

        Assert.True(result.Success);
        Assert.NotNull(result.Data);
        Assert.Equal("test@example.com", result.Data.Email);
    }

    [Fact]
    public async Task GetUserProfileAsync_ReturnsError_WhenUserNotFound()
    {
        _mockUserManager.Setup(m => m.FindByIdAsync("notfound")).ReturnsAsync((ApplicationUser)null!);

        var result = await _service.GetUserProfileAsync("notfound");

        Assert.False(result.Success);
        Assert.Equal("User not found.", result.Message);
    }

    [Fact]
    public async Task GetUserByIdAsync_ReturnsUser_WhenUserExists()
    {
        var user = new ApplicationUser
        {
            Id = "2",
            Email = "user2@example.com",
            FirstName = "User",
            LastName = "Two",
            City = "City2",
            State = "State2",
        };
        _mockUserManager.Setup(m => m.FindByIdAsync("2")).ReturnsAsync(user);

        var result = await _service.GetUserByIdAsync("2");

        Assert.Equal(user, result);
    }

    [Fact]
    public async Task GetUserByIdAsync_ReturnsNull_WhenUserDoesNotExist()
    {
        _mockUserManager.Setup(m => m.FindByIdAsync("none")).ReturnsAsync((ApplicationUser)null!);

        var result = await _service.GetUserByIdAsync("none");

        Assert.Null(result);
    }

    [Fact]
    public async Task UpdateProfileAsync_ReturnsSuccess_WhenUpdateIsValid()
    {
        var dto = new UpdateProfileRequestDto
        {
            Status = OperationStatus.Ok,
            UserId = "3",
            FirstName = "New",
            LastName = "Name",
            City = "Town",
            State = "ST",
            Email = "user@example.com",
        };

        var user = new ApplicationUser
        {
            Id = "3",
            Email = dto.Email,
            FirstName = dto.FirstName,
            LastName = dto.LastName,
            City = dto.City,
            State = dto.State,
        };

        _mockUserManager.Setup(x => x.FindByIdAsync(dto.UserId)).ReturnsAsync(user);
        _mockUserManager.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(false);
        _mockUserManager.Setup(x => x.UpdateAsync(user)).ReturnsAsync(IdentityResult.Success);

        var result = await _service.UpdateProfileAsync(dto);

        Assert.True(result.Success);
        Assert.Equal("Profile updated.", result.Message);
        Assert.Equal(OperationStatus.Ok, result.Data!.Status);
    }

    [Fact]
    public async Task UpdateProfileAsync_ReturnsError_WhenUserNotFound()
    {
        var dto = new UpdateProfileRequestDto
        {
            Status = OperationStatus.Ok,
            UserId = "unknown",
            FirstName = "John",
            LastName = "Doe",
            Email = "john@doe.com",
            City = "New York",
            State = "NY"
        };
        _mockUserManager.Setup(x => x.FindByIdAsync(dto.UserId)).ReturnsAsync((ApplicationUser)null!);

        var result = await _service.UpdateProfileAsync(dto);

        Assert.False(result.Success);
        Assert.Equal("User not found.", result.Message);
    }

    [Fact]
    public async Task UpdateProfileAsync_ReturnsError_WhenUserIsLockedOut()
    {
        var dto = new UpdateProfileRequestDto
        {
            Status = OperationStatus.Ok,
            UserId = "locked",
            FirstName = "John",
            LastName = "Doe",
            Email = "john@doe.com",
            City = "New York",
            State = "NY"
        };
        var user = new ApplicationUser
        {
            Id = "locked",
            FirstName = dto.FirstName,
            LastName = dto.LastName,
            City = dto.City,
            State = dto.State,
        };

        _mockUserManager.Setup(x => x.FindByIdAsync(dto.UserId)).ReturnsAsync(user);
        _mockUserManager.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(true);

        var result = await _service.UpdateProfileAsync(dto);

        Assert.False(result.Success);
        Assert.Equal("Account is locked. Try again later.", result.Message);
    }

    [Fact]
    public async Task UpdateProfileAsync_ReturnsError_WhenUpdateFails()
    {
        var dto = new UpdateProfileRequestDto
        {
            Status = OperationStatus.Ok,
            UserId = "fail",
            FirstName = "John",
            LastName = "Doe",
            Email = "john@doe.com",
            City = "New York",
            State = "NY"
        };
        var user = new ApplicationUser
        {
            Id = "fail",
            FirstName = dto.FirstName,
            LastName = dto.LastName,
            City = dto.City,
            State = dto.State,
        };

        _mockUserManager.Setup(x => x.FindByIdAsync(dto.UserId)).ReturnsAsync(user);
        _mockUserManager.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(false);
        _mockUserManager.Setup(x => x.UpdateAsync(user))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "DB Error" }));

        var result = await _service.UpdateProfileAsync(dto);

        Assert.False(result.Success);
        Assert.Contains("DB Error", result.Error!.Errors!);
    }

    [Fact]
    public async Task ConfirmPasswordChangeAsync_ReturnsError_WhenUserNotFound()
    {
        var dto = new ConfirmPasswordRequestDto { UserId = "missing" };
        _mockUserManager.Setup(x => x.FindByIdAsync(dto.UserId)).ReturnsAsync((ApplicationUser)null!);

        var result = await _service.ConfirmPasswordChangeAsync(dto);

        Assert.False(result.Success);
        Assert.Equal("User not found.", result.Message);
    }

    [Fact]
    public async Task ConfirmPasswordChangeAsync_ReturnsError_WhenTokenIsMissing()
    {
        var dto = new ConfirmPasswordRequestDto { UserId = "pass2", Token = "" };
        var user = new ApplicationUser
        {
            Id = "pass2",
            FirstName = "John",
            LastName = "Doe",
            City = "New York",
            State = "NY",
        };

        _mockUserManager.Setup(x => x.FindByIdAsync(dto.UserId)).ReturnsAsync(user);

        var result = await _service.ConfirmPasswordChangeAsync(dto);

        Assert.False(result.Success);
        Assert.Equal("Reset token is required.", result.Message);
    }

    [Fact]
    public async Task ConfirmPasswordChangeAsync_ReturnsError_WhenUserIsLockedOut()
    {
        var dto = new ConfirmPasswordRequestDto { UserId = "pass3", Token = "token" };
        var user = new ApplicationUser
        {
            Id = "pass3",
            FirstName = "John",
            LastName = "Doe",
            City = "New York",
            State = "NY",
        };

        _mockUserManager.Setup(x => x.FindByIdAsync(dto.UserId)).ReturnsAsync(user);
        _mockUserManager.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(true);

        var result = await _service.ConfirmPasswordChangeAsync(dto);

        Assert.False(result.Success);
        Assert.Equal("Account is locked. Try again later.", result.Message);
    }

    [Fact]
    public async Task ConfirmPasswordChangeAsync_ReturnsError_WhenResetFails()
    {
        var dto = new ConfirmPasswordRequestDto { UserId = "fail", Token = "bad-token", NewPassword = "BadPass" };
        var user = new ApplicationUser
        {
            Id = "fail",
            FirstName = "John",
            LastName = "Doe",
            City = "New York",
            State = "NY",
        };

        _mockUserManager.Setup(x => x.FindByIdAsync(dto.UserId)).ReturnsAsync(user);
        _mockUserManager.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(false);
        _mockUserManager.Setup(x => x.ResetPasswordAsync(user, dto.Token, dto.NewPassword))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "Invalid token" }));

        var result = await _service.ConfirmPasswordChangeAsync(dto);

        Assert.False(result.Success);
        Assert.Contains("Invalid token", result.Error!.Errors!);
    }

    [Fact]
    public async Task RequestEmailChangeAsync_ReturnsSuccess_WhenValid()
    {
        var dto = new ChangeEmailRequestDto
        {
            UserId = "e1",
            NewEmail = "new@example.com",
            Scheme = "https",
            Host = new HostString("example.com")
        };

        var user = new ApplicationUser
        {
            Id = "e1",
            Email = "old@example.com",
            FirstName = "John",
            LastName = "Doe",
            City = "New York",
            State = "NY",
        };

        _mockUserManager.Setup(x => x.FindByIdAsync(dto.UserId)).ReturnsAsync(user);
        _mockUserManager.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(false);
        _mockUserManager.Setup(x => x.GenerateChangeEmailTokenAsync(user, dto.NewEmail))
            .ReturnsAsync("email-token");

        _mockUrlBuilderService.Setup(x => x.BuildEmailChangeCallbackUrl(It.IsAny<EmailChangeRequest>()))
            .Returns("https://example.com/confirm");

        var result = await _service.RequestEmailChangeAsync(dto);

        Assert.True(result.Success);
        Assert.Equal("Email change requested.", result.Message);
    }

    [Fact]
    public async Task RequestEmailChangeAsync_ReturnsError_WhenUserNotFound()
    {
        var dto = new ChangeEmailRequestDto { UserId = "missing" };
        _mockUserManager.Setup(x => x.FindByIdAsync(dto.UserId)).ReturnsAsync((ApplicationUser)null!);

        var result = await _service.RequestEmailChangeAsync(dto);

        Assert.False(result.Success);
        Assert.Equal("User not found.", result.Message);
    }

    [Fact]
    public async Task RequestEmailChangeAsync_ReturnsError_WhenUserLockedOut()
    {
        var dto = new ChangeEmailRequestDto { UserId = "locked" };
        var user = new ApplicationUser
        {
            Id = "locked",
            FirstName = "John",
            LastName = "Doe",
            City = "New York",
            State = "NY",
        };

        _mockUserManager.Setup(x => x.FindByIdAsync(dto.UserId)).ReturnsAsync(user);
        _mockUserManager.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(true);

        var result = await _service.RequestEmailChangeAsync(dto);

        Assert.False(result.Success);
        Assert.Equal("Account is locked. Try again later.", result.Message);
    }

    [Fact]
    public async Task ConfirmEmailChangeAsync_ReturnsError_WhenUserNotFound()
    {
        var dto = new ConfirmEmailRequestDto { UserId = "none" };
        _mockUserManager.Setup(x => x.FindByIdAsync(dto.UserId)).ReturnsAsync((ApplicationUser)null!);

        var result = await _service.ConfirmEmailChangeAsync(dto);

        Assert.False(result.Success);
        Assert.Equal("User not found.", result.Message);
    }

    [Fact]
    public async Task ConfirmEmailChangeAsync_ReturnsError_WhenUserLockedOut()
    {
        var dto = new ConfirmEmailRequestDto { UserId = "locked" };
        var user = new ApplicationUser
        {
            Id = "locked",
            FirstName = "John",
            LastName = "Doe",
            City = "New York",
            State = "NY",
        };

        _mockUserManager.Setup(x => x.FindByIdAsync(dto.UserId)).ReturnsAsync(user);
        _mockUserManager.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(true);

        var result = await _service.ConfirmEmailChangeAsync(dto);

        Assert.False(result.Success);
        Assert.Equal("Account is locked. Try again later.", result.Message);
    }

    [Fact]
    public async Task ConfirmEmailChangeAsync_ReturnsError_WhenChangeFails()
    {
        var dto = new ConfirmEmailRequestDto
        {
            UserId = "fail",
            NewEmail = "fail@example.com",
            Token = "bad-token"
        };

        var user = new ApplicationUser
        {
            Id = "fail",
            FirstName = "John",
            LastName = "Doe",
            City = "New York",
            State = "NY",
        };

        _mockUserManager.Setup(x => x.FindByIdAsync(dto.UserId)).ReturnsAsync(user);
        _mockUserManager.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(false);
        _mockUserManager.Setup(x => x.ChangeEmailAsync(user, dto.NewEmail, dto.Token))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "Invalid token" }));

        var result = await _service.ConfirmEmailChangeAsync(dto);

        Assert.False(result.Success);
        Assert.Contains("Invalid token", result.Error!.Errors!);
    }

    [Fact]
    public async Task DeleteAccountAsync_ReturnsSuccess_WhenConfirmedAndValid()
    {
        var dto = new DeleteAccountRequestDto { UserId = "d1", Confirm = true };
        var user = new ApplicationUser
        {
            Id = "d1",
            FirstName = "John",
            LastName = "Doe",
            City = "New York",
            State = "NY",
        };

        _mockUserManager.Setup(x => x.FindByIdAsync(dto.UserId)).ReturnsAsync(user);
        _mockUserManager.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(false);
        _mockUserManager.Setup(x => x.DeleteAsync(user)).ReturnsAsync(IdentityResult.Success);

        var result = await _service.DeleteAccountAsync(dto);

        Assert.True(result.Success);
        Assert.Equal("Account deleted.", result.Message);
        Assert.Equal(OperationStatus.Ok, result.Data!.Status);
    }

    [Fact]
    public async Task DeleteAccountAsync_ReturnsError_WhenUserNotFound()
    {
        var dto = new DeleteAccountRequestDto { UserId = "none", Confirm = true };
        _mockUserManager.Setup(x => x.FindByIdAsync(dto.UserId)).ReturnsAsync((ApplicationUser)null!);

        var result = await _service.DeleteAccountAsync(dto);

        Assert.False(result.Success);
        Assert.Equal("User not found.", result.Message);
    }

    [Fact]
    public async Task DeleteAccountAsync_ReturnsError_WhenNotConfirmed()
    {
        var dto = new DeleteAccountRequestDto { UserId = "d2", Confirm = false };
        var user = new ApplicationUser
        {
            Id = "d2",
            FirstName = "John",
            LastName = "Doe",
            City = "New York",
            State = "NY",
        };

        _mockUserManager.Setup(x => x.FindByIdAsync(dto.UserId)).ReturnsAsync(user);

        var result = await _service.DeleteAccountAsync(dto);

        Assert.False(result.Success);
        Assert.Equal("Account deletion not confirmed.", result.Message);
    }

    [Fact]
    public async Task DeleteAccountAsync_ReturnsError_WhenUserLockedOut()
    {
        var dto = new DeleteAccountRequestDto { UserId = "locked", Confirm = true };
        var user = new ApplicationUser
        {
            Id = "locked",
            FirstName = "John",
            LastName = "Doe",
            City = "New York",
            State = "NY",
        };

        _mockUserManager.Setup(x => x.FindByIdAsync(dto.UserId)).ReturnsAsync(user);
        _mockUserManager.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(true);

        var result = await _service.DeleteAccountAsync(dto);

        Assert.False(result.Success);
        Assert.Equal("Account is locked. Try again later.", result.Message);
    }

    [Fact]
    public async Task DeleteAccountAsync_ReturnsError_WhenDeleteFails()
    {
        var dto = new DeleteAccountRequestDto { UserId = "fail", Confirm = true };
        var user = new ApplicationUser
        {
            Id = "fail",
            FirstName = "John",
            LastName = "Doe",
            City = "New York",
            State = "NY",
        };

        _mockUserManager.Setup(x => x.FindByIdAsync(dto.UserId)).ReturnsAsync(user);
        _mockUserManager.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(false);
        _mockUserManager.Setup(x => x.DeleteAsync(user))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "DB error" }));

        var result = await _service.DeleteAccountAsync(dto);

        Assert.False(result.Success);
        Assert.Contains("DB error", result.Error!.Errors!);
    }

    [Fact]
    public async Task ConfirmEmailChangeAsync_ReturnsSuccess_WhenValid()
    {
        var dto = new ConfirmEmailRequestDto
        {
            UserId = "c1",
            NewEmail = "confirm@example.com",
            Token = "confirm-token"
        };

        var user = new ApplicationUser
        {
            Id = "c1",
            FirstName = "John",
            LastName = "Doe",
            City = "New York",
            State = "NY",
        };

        _mockUserManager.Setup(x => x.FindByIdAsync(dto.UserId)).ReturnsAsync(user);
        _mockUserManager.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(false);
        _mockUserManager.Setup(x => x.ChangeEmailAsync(user, dto.NewEmail, dto.Token))
            .ReturnsAsync(IdentityResult.Success);

        var result = await _service.ConfirmEmailChangeAsync(dto);

        Assert.True(result.Success);
        Assert.Equal("Email change confirmed.", result.Message);
        Assert.Equal("Email successfully updated.", result.Data!.Description);
    }
    
    [Fact]
    public async Task ToggleTwoFactorAsync_ReturnsError_WhenUserNotFound()
    {
        var dto = new ToggleTwoFactorRequestDto
        {
            UserId = "none",
            Status = OperationStatus.Ok
        };
        _mockUserManager.Setup(x => x.FindByIdAsync(dto.UserId)).ReturnsAsync((ApplicationUser)null!);

        var result = await _service.ToggleTwoFactorAsync(dto);

        Assert.False(result.Success);
        Assert.Equal("User not found.", result.Message);
    }

    [Fact]
    public async Task ToggleTwoFactorAsync_ReturnsError_WhenUserLockedOut()
    {
        var dto = new ToggleTwoFactorRequestDto
        {
            UserId = "locked",
            Status = OperationStatus.Ok
        };
        var user = new ApplicationUser
        {
            Id = "locked",
            FirstName = "John",
            LastName = "Doe",
            City = "New York",
            State = "NY",
        };

        _mockUserManager.Setup(x => x.FindByIdAsync(dto.UserId)).ReturnsAsync(user);
        _mockUserManager.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(true);

        var result = await _service.ToggleTwoFactorAsync(dto);

        Assert.False(result.Success);
        Assert.Equal("Account is locked. Try again later.", result.Message);
    }

    [Fact]
    public async Task ToggleTwoFactorAsync_ReturnsError_WhenSetFails()
    {
        var dto = new ToggleTwoFactorRequestDto
        {
            UserId = "fail",
            IsEnabled = false,
            Status = OperationStatus.Ok
        };
        var user = new ApplicationUser
        {
            Id = "fail",
            FirstName = "John",
            LastName = "Doe",
            City = "New York",
            State = "NY",
        };

        _mockUserManager.Setup(x => x.FindByIdAsync(dto.UserId)).ReturnsAsync(user);
        _mockUserManager.Setup(x => x.IsLockedOutAsync(user)).ReturnsAsync(false);
        _mockUserManager.Setup(x => x.SetTwoFactorEnabledAsync(user, dto.IsEnabled))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "Failed to update 2FA" }));

        var result = await _service.ToggleTwoFactorAsync(dto);

        Assert.False(result.Success);
        Assert.Contains("Failed to update 2FA", result.Error!.Errors!);
    }
    
}