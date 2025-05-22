using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using My_Social_Secure_Api.Data;
using My_Social_Secure_Api.Enums.Common;
using My_Social_Secure_Api.Interfaces.Services.Auth;
using My_Social_Secure_Api.Interfaces.Services.DeviceRecognition;
using My_Social_Secure_Api.Interfaces.Services.GeoLocation;
using My_Social_Secure_Api.Interfaces.Services.LoginTracking;
using My_Social_Secure_Api.Interfaces.Services.Notifications;
using My_Social_Secure_Api.Interfaces.Services.Security;
using My_Social_Secure_Api.Interfaces.Services.Utilities;
using My_Social_Secure_Api.Models.Auth;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Auth;
using My_Social_Secure_Api.Models.Identity;
using My_Social_Secure_Api.Models.Dtos.Registration;
using My_Social_Secure_Api.Models.Dtos.Security;
using My_Social_Secure_Api.Models.Notifications;
using My_Social_Secure_Api.Services.Auth;

public class AuthServiceTests
{
    private readonly AuthService _service;
    private readonly Mock<UserManager<ApplicationUser>> _mockUserManager;
    private readonly Mock<SignInManager<ApplicationUser>> _mockSignInManager;
    private readonly Mock<IJwtTokenGenerator> _mockJwtTokenGenerator = new();
    private readonly Mock<IRefreshTokenService> _mockRefreshTokenService = new();
    private readonly Mock<ILoginAlertService> _mockLoginAlertService = new();
    private readonly Mock<ILoginHistoryService> _mockLoginHistoryService = new();
    private readonly Mock<IDeviceRecognitionService> _mockDeviceRecognitionService = new();
    private readonly Mock<IIpGeolocationService> _mockGeoLocationService = new();
    private readonly Mock<IUserEmailService> _mockUserEmailService = new();
    private readonly Mock<IUrlBuilderService> _mockUrlBuilderService = new();
    private readonly Mock<IHttpContextAccessor> _mockHttpContextAccessor = new();
    private readonly ApplicationDbContext _context;

    public AuthServiceTests()
    {
        var store = new Mock<IUserStore<ApplicationUser>>();
        _mockUserManager =
            new Mock<UserManager<ApplicationUser>>(store.Object, null!, null!, null!, null!, null!, null!, null!,
                null!);
        var contextAccessor = new Mock<IHttpContextAccessor>();
        var context = new DefaultHttpContext
        {
            Items =
            {
                ["X-Correlation-ID"] = "test-correlation-id"
            }
        };
        contextAccessor.Setup(x => x.HttpContext).Returns(context);
        _mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(context);

        _mockSignInManager = new Mock<SignInManager<ApplicationUser>>(
            _mockUserManager.Object,
            contextAccessor.Object,
            new Mock<IUserClaimsPrincipalFactory<ApplicationUser>>().Object,
            null!, null!, null!, null!);

        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase("AuthServiceTests")
            .Options;

        _context = new ApplicationDbContext(options);

        _service = new AuthService(
            new Mock<ILogger<AuthService>>().Object,
            _context,
            _mockUserManager.Object,
            _mockSignInManager.Object,
            _mockJwtTokenGenerator.Object,
            _mockRefreshTokenService.Object,
            _mockLoginAlertService.Object,
            _mockLoginHistoryService.Object,
            _mockDeviceRecognitionService.Object,
            _mockGeoLocationService.Object,
            _mockUserEmailService.Object,
            _mockUrlBuilderService.Object,
            _mockHttpContextAccessor.Object);
    }

    [Fact]
    public async Task RegisterNewUserAsync_EmailAlreadyExists_ReturnsError()
    {
        _mockUserManager.Setup(m => m.FindByEmailAsync("taken@example.com"))
            .ReturnsAsync(new ApplicationUser
            {
                FirstName = "John",
                LastName = "Doe",
                City = "New York",
                State = "NY",
            });

        var dto = new RegisterRequestDto { Email = "taken@example.com", UserName = "tester" };
        var result = await _service.RegisterNewUserAsync(dto);

        Assert.False(result.Success);
        Assert.Equal("Email is already in use.", result.Message);
    }

    [Fact]
    public async Task RegisterNewUserAsync_UserNameTaken_ReturnsError()
    {
        _mockUserManager.Setup(m => m.FindByEmailAsync(It.IsAny<string>()))
            .ReturnsAsync((ApplicationUser)null!);
        _mockUserManager.Setup(m => m.FindByNameAsync("tester"))
            .ReturnsAsync(new ApplicationUser
            {
                FirstName = "John",
                LastName = "Doe",
                City = "New York",
                State = "NY",
            });

        var dto = new RegisterRequestDto { Email = "user@example.com", UserName = "tester" };
        var result = await _service.RegisterNewUserAsync(dto);

        Assert.False(result.Success);
        Assert.Equal("Username is already in use.", result.Message);
    }

    [Fact]
    public async Task RegisterNewUserAsync_Success_ReturnsSuccess()
    {
        var user = new ApplicationUser
        {
            Id = "u123",
            Email = "new@example.com",
            UserName = "new-user",
            FirstName = "First",
            LastName = "Last",
            City = "New York",
            State = "NY",
        };

        _mockUserManager.Setup(m => m.FindByEmailAsync(user.Email)).ReturnsAsync((ApplicationUser)null!);
        _mockUserManager.Setup(m => m.FindByNameAsync(user.UserName)).ReturnsAsync((ApplicationUser)null!);
        _mockUserManager
            .Setup(x => x.GenerateEmailConfirmationTokenAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync("fake-token");
        _mockUserEmailService
            .Setup(x => x.SendEmailConfirmationAsync(It.IsAny<ApplicationUser>(), It.IsAny<LoginMetadata>()))
            .Returns(Task.CompletedTask);
        _mockUrlBuilderService
            .Setup(x => x.BuildEmailConfirmationUrl(It.IsAny<EmailConfirmationRequest>()))
            .Returns("https://example.com/confirm?userId=u123&token=fake-token");
        _mockUserManager.Setup(m => m.CreateAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()))
            .ReturnsAsync(IdentityResult.Success);
        _mockUserManager.Setup(m => m.AddToRoleAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()))
            .ReturnsAsync(IdentityResult.Success);
        
        
        var dto = new RegisterRequestDto
        {
            Email = user.Email,
            UserName = user.UserName,
            Password = "Password123!",
            ConfirmPassword = "Password123!",
            FirstName = "First",
            LastName = "Last",
            City = "New York",
            State = "NY",
            Scheme = "https",
            Host = new HostString("example.com")
        };

        var result = await _service.RegisterNewUserAsync(dto);


        Assert.True(result.Success);
        Assert.NotNull(result.Data);
        Assert.Equal("Registration successful.", result.Message);
    }
    
    [Fact]
    public async Task LoginAsync_ReturnsError_WhenUserNotFound()
    {
        _mockUserManager.Setup(x => x.FindByEmailAsync("noone@example.com"))
            .ReturnsAsync((ApplicationUser)null!);

        var dto = new LoginRequestDto() { UserName = "user-name", Password = "irrelevant" };
        var result = await _service.LoginUserAsync(dto);

        Assert.False(result.Success);
        Assert.Equal("User not found.", result.Message);
        Assert.Equal(OperationStatus.Error, result.Error!.Status);
        Assert.Equal("NOT_FOUND", result.Error!.Code);
        Assert.Equal(ErrorCategory.NotFound, result.Error!.Category);
    }

    [Fact]
    public async Task LoginAsync_ReturnsError_WhenPasswordInvalid()
    {
        var user = new ApplicationUser
        {
            Id = "u1",
            UserName = "JohnDoe",
            Email = "user@example.com",
            FirstName = "John",
            LastName = "Doe",
            City = "New York",
            State = "NY",
        };

        _mockUserManager.Setup(x => x.FindByNameAsync(user.UserName))
            .ReturnsAsync(user);

        _mockSignInManager.Setup(x => x.CheckPasswordSignInAsync(user, "wrong-pass", false))
            .ReturnsAsync(SignInResult.Failed);

        var dto = new LoginRequestDto { UserName = user.UserName, Password = "wrong-pass" };
        var result = await _service.LoginUserAsync(dto);

        Assert.False(result.Success);
        Assert.Equal("Incorrect password.", result.Message);
        Assert.Equal(OperationStatus.Error, result.Error!.Status);
        Assert.Equal("VALIDATION_ERROR", result.Error!.Code);
        Assert.Equal(ErrorCategory.Validation, result.Error!.Category);
    }

    [Fact]
    public async Task LoginAsync_ReturnsError_WhenTwoFactorRequired()
    {
        var user = new ApplicationUser
        {
            Id = "u2",
            UserName = "JaneSmith",
            Email = "user2@example.com",
            FirstName = "Jane",
            LastName = "Smith",
            City = "Los Angeles",
            State = "CA",
            TwoFactorEnabled = true
        };

        _mockUserManager.Setup(x => x.FindByNameAsync(user.UserName)).ReturnsAsync(user);
        _mockUserManager.Setup(x => x.CheckPasswordAsync(user, It.IsAny<string>())).ReturnsAsync(true);
        _mockSignInManager.Setup(x => x.PasswordSignInAsync(user, It.IsAny<string>(), false, true))
            .ReturnsAsync(SignInResult.TwoFactorRequired);

        var dto = new LoginRequestDto { UserName = user.UserName, Password = "password" };
        var result = await _service.LoginUserAsync(dto);

        Assert.False(result.Success);
        Assert.Equal("Two-factor authentication required.", result.Message);
        Assert.Equal(OperationStatus.ActionRequired, result.Error!.Status);
        Assert.Equal("REQUIRES_2FA", result.Error!.Code);
        Assert.Equal(ErrorCategory.Authentication, result.Error!.Category);
    }


    [Fact]
    public async Task LoginAsync_ReturnsSuccess_WhenCredentialsAreValid()
    {
        var user = new ApplicationUser
        {
            Id = "u3",
            UserName = "valid-user",
            Email = "valid@example.com",
            FirstName = "Valid",
            LastName = "User",
            City = "San Francisco",
            State = "CA",
        };

        _mockUserManager.Setup(x => x.FindByNameAsync(user.UserName)).ReturnsAsync(user);
        _mockUserManager.Setup(x => x.CheckPasswordAsync(user, It.IsAny<string>())).ReturnsAsync(true); // ✅ Needed
        _mockSignInManager.Setup(x => x.PasswordSignInAsync(user, It.IsAny<string>(), false, true))
            .ReturnsAsync(SignInResult.Success);
        _mockJwtTokenGenerator.Setup(j => j.GenerateToken(user)).Returns("access-token");

        var dto = new LoginRequestDto { UserName = user.UserName, Password = "password" }; // Use UserName, not Email
        var result = await _service.LoginUserAsync(dto);

        Assert.True(result.Success);
        Assert.Equal("access-token", result.Data!.Token);
        Assert.Equal(OperationStatus.Ok, result.Data.Status);
    }
    
    [Fact]
    public async Task LoginWithTwoFactorAsync_ReturnsError_WhenUserNotFound()
    {
        _mockUserManager.Setup(x => x.FindByEmailAsync("unknown@example.com"))
            .ReturnsAsync((ApplicationUser)null!);

        var dto = new VerifyTwoFactorDto { UserName = "valid-user", Code = "123456" };
        var result = await _service.LoginUserWith2FaAsync(dto);

        Assert.False(result.Success);
        Assert.Equal("User not found.", result.Message);
    }

    [Fact]
    public async Task LoginWithTwoFactorAsync_ReturnsError_WhenCodeInvalid()
    {
        var user = new ApplicationUser
        {
            Id = "u4",
            UserName = "2fa-user",
            Email = "2fa@example.com",
            FirstName = "John",
            LastName = "Doe",
            City = "New York",
            State = "NY"
        };
        _mockUserManager.Setup(x => x.FindByNameAsync(user.UserName)).ReturnsAsync(user);
        _mockSignInManager
            .Setup(x => x.TwoFactorSignInAsync("Email", "bad-code", false, false))
            .ReturnsAsync(SignInResult.Failed);
        
        var dto = new VerifyTwoFactorDto { UserName = user.UserName, Code = "bad-code", Host = new HostString("example.com")};
        var result = await _service.LoginUserWith2FaAsync(dto);

        Assert.False(result.Success);
        Assert.Equal("Invalid 2FA code.", result.Message);
    }

    [Fact]
    public async Task LoginWithTwoFactorAsync_ReturnsSuccess_WhenCodeIsValid()
    {
        var user = new ApplicationUser
        {
            Id = "u5",
            Email = "2fauser@example.com",
            UserName = "2fa-user",
            FirstName = "Jane",
            LastName = "Smith",
            City = "Los Angeles",
            State = "CA",
        };
        _mockUserManager.Setup(x => x.FindByNameAsync(user.UserName)).ReturnsAsync(user);
        _mockSignInManager
            .Setup(x => x.TwoFactorSignInAsync("Email", "123456", false, false))
            .ReturnsAsync(SignInResult.Success);
        _mockJwtTokenGenerator.Setup(j => j.GenerateToken(user)).Returns("access-token");
        _mockRefreshTokenService.Setup(r => r.CreateRefreshTokenAsync(user)).ReturnsAsync(new ApiResponse<TokenDto>
        {
            Success = true,
            Data = new TokenDto
            {
                Token = "access-token",
                Status = OperationStatus.Ok
            }
        });

        var dto = new VerifyTwoFactorDto { UserName = user.UserName, Code = "123456" };
        var result = await _service.LoginUserWith2FaAsync(dto);

        Assert.True(result.Success);
        Assert.Equal("access-token", result.Data!.Token);
    }

    [Fact]
    public async Task LogoutAsync_ClearsSecurityStamp_And_RemovesRefreshToken()
    {
        var user = new ApplicationUser
        {
            Id = "u7",
            Email = "logout@example.com",
            FirstName = "John",
            LastName = "Doe",
            City = "New York",
            State = "NY",
        };
        _mockUserManager.Setup(x => x.FindByIdAsync(user.Id)).ReturnsAsync(user);
        _mockUserManager.Setup(x => x.UpdateSecurityStampAsync(user)).ReturnsAsync(IdentityResult.Success);
        
        // Seed refresh token
        _context.RefreshTokens.Add(new My_Social_Secure_Api.Models.Auth.RefreshTokenModel
        {
            UserId = user.Id,
            Token = "existing-refresh-token"
        });
        await _context.SaveChangesAsync();

        var dto = new LogoutRequestDto
        {
            UserId = user.Id,
            Token = "existing-refresh-token"
        };
        
       var result = await _service.LogoutUserAsync(dto);

        Assert.True(result.Success);
        Assert.Equal("Logged out successfully.", result.Message);
        _mockRefreshTokenService.Verify(x => x.RevokeTokenAsync(dto.Token), Times.Once);
    }

    [Fact]
    public async Task LogoutAsync_ReturnsError_WhenTokenNotFound()
    {
        _mockUserManager.Setup(x => x.FindByIdAsync("invalid-id"))
            .ReturnsAsync((ApplicationUser)null!);

        var dto = new LogoutRequestDto
        {
            UserId = "non-existent-id",
            Token = string.Empty
        };
        
        var result = await _service.LogoutUserAsync(dto);
        Assert.False(result.Success);
        Assert.Equal("A valid token must be provided.", result.Message);
    }
}