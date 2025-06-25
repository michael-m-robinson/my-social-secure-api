using My_Social_Secure_Api.Enums.Common;
using My_Social_Secure_Api.Interfaces.Services.Auth;
using My_Social_Secure_Api.Interfaces.Services.DeviceRecognition;
using My_Social_Secure_Api.Interfaces.Services.GeoLocation;
using My_Social_Secure_Api.Interfaces.Services.LoginTracking;
using My_Social_Secure_Api.Interfaces.Services.Notifications;
using My_Social_Secure_Api.Interfaces.Services.Security;
using My_Social_Secure_Api.Interfaces.Services.Utilities;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Auth;
using My_Social_Secure_Api.Models.Dtos.Common;
using My_Social_Secure_Api.Models.Dtos.Security;
using My_Social_Secure_Api.Models.Identity;
using My_Social_Secure_Api.Models.Notifications;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using My_Social_Secure_Api.Models.Auth;
using My_Social_Secure_Api.Models.Dtos.Registration;
using System.Net.Mail;

// ReSharper disable ConvertToPrimaryConstructor

namespace My_Social_Secure_Api.Services.Auth;

public class AuthService : IAuthService
{
    private readonly ILogger<AuthService> _logger;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IJwtTokenGenerator _jwtTokenGenerator;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly ILoginAlertService _loginAlertService;
    private readonly ILoginHistoryService _loginHistoryService;
    private readonly IDeviceRecognitionService _deviceRecognitionService;
    private readonly IIpGeolocationService _geoLocationService;
    private readonly IUserEmailService _emailSender;
    private readonly IUrlBuilderService _urlBuilderService;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public AuthService(ILogger<AuthService> logger,
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IJwtTokenGenerator jwtTokenGenerator,
        IRefreshTokenService refreshTokenService,
        ILoginAlertService loginAlertService,
        ILoginHistoryService loginHistoryService,
        IDeviceRecognitionService deviceRecognitionService,
        IIpGeolocationService geoLocationService,
        IUserEmailService emailSender,
        IUrlBuilderService urlBuilderService,
        IHttpContextAccessor httpContextAccessor)
    {
        _logger = logger;
        _userManager = userManager;
        _signInManager = signInManager;
        _jwtTokenGenerator = jwtTokenGenerator;
        _refreshTokenService = refreshTokenService;
        _loginAlertService = loginAlertService;
        _loginHistoryService = loginHistoryService;
        _deviceRecognitionService = deviceRecognitionService;
        _geoLocationService = geoLocationService;
        _emailSender = emailSender;
        _urlBuilderService = urlBuilderService;
        _httpContextAccessor = httpContextAccessor;
    }

    private string CorrelationId => _httpContextAccessor.HttpContext?.Items["X-Correlation-ID"]?.ToString() ?? "none";

    public async Task<ApiResponse<RegisterDto>> RegisterNewUserAsync(RegisterRequestDto dto)
    {
        try
        {
            _logger.LogInformation("RegisterNewUser started. CorrelationId: {CorrelationId}", CorrelationId);
            var ip = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            _logger.LogInformation("RegisterNewUser requested from IP: {IpAddress}", ip);

            var existingEmail = await _userManager.FindByEmailAsync(dto.Email);
            if (existingEmail != null)
                return AuthenticationErrorResponse<RegisterDto>("Email is already in use.", "EMAIL_IN_USE");

            var existingUserName = await _userManager.FindByNameAsync(dto.UserName);
            if (existingUserName != null)
                return AuthenticationErrorResponse<RegisterDto>("Username is already in use.", "USERNAME_IN_USE");

            if (dto.Password != dto.ConfirmPassword)
                return AuthenticationErrorResponse<RegisterDto>("Password and confirm password do not match.",
                    "PASSWORD_MISMATCH");

            if (!IsValidEmail(dto.Email))
                return ValidationErrorResponse<RegisterDto>("Invalid email format.", "INVALID_EMAIL_FORMAT");

            var user = new ApplicationUser
            {
                UserName = dto.UserName,
                Email = dto.Email,
                FirstName = dto.FirstName,
                LastName = dto.LastName,
                TwoFactorEnabled = dto.TwoFactorEnabled,
                City = dto.City,
                State = dto.State,
            };

            var result = await _userManager.CreateAsync(user, dto.Password);
            if (!result.Succeeded)
            {
                _logger.LogWarning("User creation failed. CorrelationId: {CorrelationId}", CorrelationId);
                return AuthenticationErrorResponse<RegisterDto>(string.Join("; ",
                    result.Errors.Select(e => e.Description)), "USER_CREATION_FAILED");
            }

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var confirmationLink = _urlBuilderService.BuildEmailConfirmationUrl(new EmailConfirmationRequest
            {
                Scheme = dto.Scheme,
                Host = dto.Host,
                UserId = user.Id,
                Token = token
            });

            if (string.IsNullOrWhiteSpace(confirmationLink))
                return InternalErrorResponse<RegisterDto>("CONFIRMATION_LINK_GENERATION_FAILED");

            await _emailSender.SendEmailConfirmationAsync(user, new LoginMetadata
            {
                RequestLink = confirmationLink,
                Domain = dto.Host.Value
            });

            var registrationData = new RegisterDto
            {
                Status = OperationStatus.Ok,
                Description =
                    "The user account was created successfully. A confirmation email has been sent to complete the registration process.",
                EmailConfirmationSent = true
            };

            return GenericSuccessResponse(registrationData, "Registration successful.");
        }
        catch (DbUpdateException dbEx)
        {
            _logger.LogError(dbEx, "Registration failed due to database error. CorrelationId: {CorrelationId}",
                CorrelationId);
            return DatabaseErrorResponse<RegisterDto>("A database error occurred during registration.",
                "DATABASE_ERROR");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An unexpected error occurred during registration. CorrelationId: {CorrelationId}",
                CorrelationId);
            return InternalErrorResponse<RegisterDto>("REGISTRATION_ERROR");
        }
    }

    public async Task<ApiResponse<OperationDto>> LoginUserAsync(LoginRequestDto dto)
    {
        try
        {
            _logger.LogInformation("LoginUserAsync. CorrelationId: {CorrelationId}", CorrelationId);
            var ip = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
            _logger.LogInformation("LoginUserAsync requested from IP: {IpAddress}", ip);

            if (string.IsNullOrWhiteSpace(dto.UserName) || string.IsNullOrWhiteSpace(dto.Password))
                return ValidationErrorResponse<OperationDto>("Username or password is empty.", "EMPTY_CREDENTIALS");

            var user = await _userManager.FindByNameAsync(dto.UserName);
            if (user == null)
                return NotFoundErrorResponse<OperationDto>("User not found.", "USER_NOT_FOUND");
            
            var signInResult =
                await _signInManager.PasswordSignInAsync(user, dto.Password, dto.RememberMe, lockoutOnFailure: true);
            
            if (signInResult.IsLockedOut)
            {
                return AuthenticationErrorResponse<OperationDto>(
                    "Your account is locked due to multiple failed login attempts. Please try again later.",
                    "ACCOUNT_LOCKED");
            }

            if (signInResult.IsNotAllowed)
            {
                if (!user.EmailConfirmed)
                    return AuthenticationErrorResponse<OperationDto>("Please confirm your email before logging in.",
                        "EMAIL_NOT_CONFIRMED");

                return AuthenticationErrorResponse<OperationDto>("Login not allowed. Please contact support.",
                    "LOGIN_NOT_ALLOWED");
            }

            if (signInResult.RequiresTwoFactor)
            {
                await _signInManager.SignInAsync(user, isPersistent: false,
                    authenticationMethod: IdentityConstants.TwoFactorUserIdScheme);

                var partialLoginToken = _jwtTokenGenerator.GenerateTemporary2FaToken(user);
                var twoFactorToken = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                var requestLink = _urlBuilderService.BuildTwoFactorCallbackUrl(new TwoFactorAuthRequest
                {
                    Scheme = dto.Scheme,
                    Host = dto.Host,
                    UserName = user.UserName!,
                    Code = twoFactorToken,
                    RememberMe = false,
                });

                await _emailSender.SendTwoFactorCodeEmailAsync(user, new LoginMetadata
                {
                    Domain = dto.Host.Value,
                    RequestLink = requestLink
                });

                return new ApiResponse<OperationDto>
                {
                    Success = false,
                    Message = "Two-factor authentication required.",
                    Error = new ApiError
                    {
                        Status = OperationStatus.ActionRequired,
                        Code = "REQUIRES_2FA",
                        Category = ErrorCategory.Authentication,
                        Errors = new List<string> { "Two-factor authentication required." }
                    },
                    Data = new OperationDto
                    {
                        Token = partialLoginToken,
                        Status = OperationStatus.ActionRequired,
                        Description = "Two-factor authentication required. Submit your 2FA code to continue."
                    }
                };
            }

            if (signInResult.Succeeded)
            {
                await _loginAlertService.HandleLoginAlertAsync(user, dto.Host.Value);

                var device = _deviceRecognitionService.GetDeviceSummary(
                    _httpContextAccessor.HttpContext?.Request.Headers["User-Agent"]);
                var location = await _geoLocationService.GetLocationAsync(ip);

                await _loginHistoryService.RecordLoginAsync(user, ip, device, location);
                return BuildSuccessfulLoginResponse(user, new ApiResponse<OperationDto>());
            }

            return AuthenticationErrorResponse<OperationDto>("Login failed.", "LOGIN_FAILED");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred during login. CorrelationId: {CorrelationId}", CorrelationId);
            return InternalErrorResponse<OperationDto>("LOGIN_ERROR");
        }
    }

    public async Task<ApiResponse<OperationDto>> LoginUserWith2FaAsync(VerifyTwoFactorDto dto)
    {
        try
        {
            _logger.LogInformation("LoginUserWith2Fa started. CorrelationId: {CorrelationId}", CorrelationId);
            var ip = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
            _logger.LogInformation("LoginUserWith2Fa requested from IP: {IpAddress}", ip);
            
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                _logger.LogWarning("User not found for 2FA login. Username: {UserName} Correlation Id: {CorrelationId}",
                    dto.UserName, CorrelationId);
                return NotFoundErrorResponse<OperationDto>("User not found.", "USER_NOT_FOUND");
            }

            var result = await _signInManager.TwoFactorSignInAsync(
                "Email", 
                SafeToken(dto.Code), 
                dto.RememberMe, 
                rememberClient: false
            );

            if (result.IsLockedOut)
                return UnauthorizedErrorResponse<OperationDto>("ACCOUNT_LOCKED");

            if (result.Succeeded)
            {
                await _loginAlertService.HandleLoginAlertAsync(user, dto.Host.Value);

                var device =
                    _deviceRecognitionService.GetDeviceSummary(
                        _httpContextAccessor.HttpContext?.Request.Headers["User-Agent"]);
                var location = await _geoLocationService.GetLocationAsync(ip);

                await _loginHistoryService.RecordLoginAsync(user, ip, device, location);
                return BuildSuccessfulLoginResponse(user, new ApiResponse<OperationDto>());
            }

            if (result.IsNotAllowed)
            {
                return AuthenticationErrorResponse<OperationDto>("Two-factor login not allowed.", "2FA_NOT_ALLOWED");
            }

            return AuthenticationErrorResponse<OperationDto>("Invalid 2FA code.", "INVALID_2FA_CODE");
        }
        catch (DbUpdateException dbEx)
        {
            _logger.LogError(dbEx, "Database update failed during 2FA login. Correlation ID: {CorrelationId}",
                CorrelationId);
            return DatabaseErrorResponse<OperationDto>("Database update failed.", "DATABASE_UPDATE_FAILED");
        }
        catch (UnauthorizedAccessException uaEx)
        {
            _logger.LogWarning(uaEx, "Unauthorized access attempt during 2FA login. Correlation ID: {CorrelationId}",
                CorrelationId);
            return UnauthorizedErrorResponse<OperationDto>("UNAUTHORIZED_ACCESS");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred during 2FA login. Correlation ID: {CorrelationId}", CorrelationId);
            return InternalErrorResponse<OperationDto>("2FA_LOGIN_ERROR");
        }
    }

    public async Task<ApiResponse<OperationDto>> LogoutUserAsync(LogoutRequestDto dto)
    {
        _logger.LogInformation("LogoutUserAsync started. CorrelationId: {CorrelationId}", CorrelationId);
        var ip = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        _logger.LogInformation("LogoutUserAsync requested from IP: {IpAddress}", ip);

        try
        {
            if (string.IsNullOrWhiteSpace(dto.Token))
                return AuthenticationErrorResponse<OperationDto>("Invalid request. Please provide a valid token.",
                    "INVALID_REQUEST");

            await _refreshTokenService.RevokeTokenAsync(dto.Token);
            await _signInManager.SignOutAsync();

            return GenericSuccessResponse(new OperationDto
            {
                Status = OperationStatus.Ok,
                Description = "The user has been logged out successfully."
            }, "Logged out successfully.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Logout failed. CorrelationId: {CorrelationId}", CorrelationId);
            return InternalErrorResponse<OperationDto>("LOGOUT_ERROR");
        }
    }

    public async Task<ApiResponse<OperationDto>> ResendRegistrationEmailConfirmation(
        ResendRegistrationEmailConfirmationDto dto)
    {
        try
        {
            _logger.LogInformation("ResendRegistrationEmailConfirmation started. CorrelationId: {CorrelationId}",
                CorrelationId);
            var ip = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
            _logger.LogInformation("ResendRegistrationEmailConfirmation reset requested from IP: {IpAddress}", ip);

            var user = await _userManager.FindByEmailAsync(dto.Email);

            if (user == null)
                return NotFoundErrorResponse<OperationDto>("User not found.", "USER_NOT_FOUND");

            if (user.EmailConfirmed)
                return ValidationErrorResponse<OperationDto>("Email already confirmed.", "EMAIL_ALREADY_CONFIRMED");

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var confirmationLink = _urlBuilderService.BuildEmailConfirmationUrl(new EmailConfirmationRequest
            {
                Scheme = dto.Scheme,
                Host = dto.Host,
                UserId = user.Id,
                Token = token
            });

            if (string.IsNullOrWhiteSpace(confirmationLink))
                return InternalErrorResponse<OperationDto>("CONFIRMATION_LINK_GENERATION_FAILED");

            await _emailSender.SendEmailConfirmationAsync(user, new LoginMetadata
            {
                RequestLink = confirmationLink,
                Domain = dto.Host.Value
            });

            return GenericSuccessResponse(new OperationDto
            {
                Status = OperationStatus.Ok,
                Description = "Confirmation email resent successfully."
            }, "Email confirmation resent.");
        }
        catch (UnauthorizedAccessException uaEx)
        {
            _logger.LogWarning(uaEx,
                "Unauthorized access attempt while resending email confirmation. Correlation ID: {CorrelationId}",
                CorrelationId);
            return UnauthorizedErrorResponse<OperationDto>("UNAUTHORIZED_ACCESS");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while resending email confirmation. Correlation ID: {CorrelationId}",
                CorrelationId);
            return InternalErrorResponse<OperationDto>("RESEND_EMAIL_CONFIRMATION_ERROR");
        }
    }

    public async Task<ApiResponse<OperationDto>> VerifyAndConfirmRegistrationEmail(RegistrationEmailConfirmationDto dto)
    {
        try
        {
            _logger.LogInformation("VerifyAndConfirmRegistrationEmail started. CorrelationId: {CorrelationId}",
                CorrelationId);
            var ip = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
            _logger.LogInformation("VerifyAndConfirmRegistrationEmail reset requested from IP: {IpAddress}", ip);

            var user = await _userManager.FindByIdAsync(dto.UserId);
            if (user == null)
                return NotFoundErrorResponse<OperationDto>("User not found.", "USER_NOT_FOUND");

            if (string.IsNullOrEmpty(dto.Token))
                return AuthenticationErrorResponse<OperationDto>("Token is required.", "TOKEN_REQUIRED");

            var result = await _userManager.ConfirmEmailAsync(user, SafeToken(dto.Token));
            if (!result.Succeeded)
            {
                return new ApiResponse<OperationDto>
                {
                    Success = false,
                    Message = string.Join("; ", result.Errors.Select(e => e.Description)),
                    Error = new ApiError
                    {
                        Status = OperationStatus.Failed,
                        Description = "We couldn’t verify your email. The link may have expired or already been used.",
                        Code = "EMAIL_CONFIRMATION_FAILED",
                        Category = ErrorCategory.Authentication,
                    }
                };
            }

            var emailData = new OperationDto
            {
                Status = OperationStatus.Ok,
                Description = "The email address has been confirmed successfully. Your account is now active."
            };

            return GenericSuccessResponse(emailData, "Email confirmed successfully.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred during email confirmation. CorrelationId: {CorrelationId}",
                CorrelationId);
            return InternalErrorResponse<OperationDto>("EMAIL_CONFIRMATION_ERROR");
        }
    }

    private ApiResponse<T> GenericSuccessResponse<T>(T data, string message) where T : BaseOperationDto => new()
    {
        Success = true,
        Message = message,
        Data = data
    };

    private ApiResponse<T> AuthenticationSuccessResponse<T>(T data, string message) where T : BaseOperationDto => new()
    {
        Success = true,
        Message = message,
        Data = data
    };

    private ApiResponse<T> AuthenticationErrorResponse<T>(string message, string code) => new()
    {
        Success = false,
        Message = message,
        Error = new ApiError
        {
            Status = OperationStatus.Failed,
            Description = "Authentication failed.",
            Code = code,
            Category = ErrorCategory.Authentication,
            Errors = [message]
        }
    };

    private ApiResponse<T> ValidationErrorResponse<T>(string message, string code) => new()
    {
        Success = false,
        Message = message,
        Error = new ApiError
        {
            Status = OperationStatus.Error,
            Code = code,
            Category = ErrorCategory.Validation,
            Description = "Some fields contain invalid or missing values.",
            Errors = new List<string> { message }
        }
    };

    private ApiResponse<T> NotFoundErrorResponse<T>(string message, string code) => new()
    {
        Success = false,
        Message = message,
        Error = new ApiError
        {
            Status = OperationStatus.Error,
            Code = code,
            Category = ErrorCategory.NotFound,
            Description = "The resource you're trying to access was not found.",
            Errors = new List<string> { message }
        }
    };

    private ApiResponse<T> UnauthorizedErrorResponse<T>(string code) => new()
    {
        Success = false,
        Message = "Access denied.",
        Error = new ApiError
        {
            Status = OperationStatus.Failed,
            Code = code,
            Category = ErrorCategory.Authorization,
            Description = "You do not have permission to access this resource.",
            Errors = new List<string> { "Access denied." }
        }
    };

    private ApiResponse<T> DatabaseErrorResponse<T>(string message, string code) => new()
    {
        Success = false,
        Message = message,
        Error = new ApiError
        {
            Status = OperationStatus.Error,
            Code = code,
            Category = ErrorCategory.Internal,
            Description = "The request could not be completed due to a database error.",
            Errors = new List<string> { message }
        }
    };

    private ApiResponse<T> InternalErrorResponse<T>(string code) => new()
    {
        Success = false,
        Message = "An internal error occurred. Please try again later.",
        Error = new ApiError
        {
            Status = OperationStatus.Error,
            Code = code,
            Category = ErrorCategory.Internal,
            Description =
                "The server encountered an unexpected condition that prevented it from fulfilling the request.",
            Errors = new List<string> { "A server error has occurred." }
        }
    };

    private ApiResponse<OperationDto> BuildSuccessfulLoginResponse(ApplicationUser user,
        ApiResponse<OperationDto> response)
    {
        var token = _jwtTokenGenerator.GenerateToken(user);

        if (string.IsNullOrEmpty(token))
        {
            _logger.LogError("Failed to generate JWT token for user {UserId}. CorrelationId: {CorrelationId}", user.Id,
                CorrelationId);
            return InternalErrorResponse<OperationDto>("TOKEN_GENERATION_FAILED");
        }

        response.Success = true;
        response.Message = "Login successful.";
        response.Data = new OperationDto
        {
            Status = OperationStatus.Ok,
            Description = "The user was successfully authenticated.",
            Token = token
        };

        return response;
    }

    private string SafeToken(string token)
    {
        return token.Replace(' ', '+');
    }

    private bool IsValidEmail(string email)
    {
        try
        {
            return !string.IsNullOrWhiteSpace(email)
                   && MailAddress.TryCreate(email, out _);
        }
        catch
        {
            return false;
        }
    }
}