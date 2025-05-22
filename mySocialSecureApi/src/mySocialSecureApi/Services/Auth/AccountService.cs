using Microsoft.AspNetCore.Identity;
using My_Social_Secure_Api.Enums.Common;
using My_Social_Secure_Api.Interfaces.Services.Auth;
using My_Social_Secure_Api.Interfaces.Services.Notifications;
using My_Social_Secure_Api.Interfaces.Services.Utilities;
using My_Social_Secure_Api.Models.Account;
using My_Social_Secure_Api.Models.Identity;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Account;
using My_Social_Secure_Api.Models.Dtos.Common;
using My_Social_Secure_Api.Models.Notifications;
using static System.String;

namespace My_Social_Secure_Api.Services.Auth;

public class AccountService(
    ILogger<AccountService> logger,
    UserManager<ApplicationUser> userManager,
    IUserEmailService emailSender,
    IUrlBuilderService urlBuilderService,
    IHttpContextAccessor httpContextAccessor)
    : IAccountService
{
    private readonly ILogger<AccountService> _logger = logger;
    private readonly UserManager<ApplicationUser> _userManager = userManager;
    private readonly IUserEmailService _emailSender = emailSender;
    private readonly IUrlBuilderService _urlBuilderService = urlBuilderService;
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;

    private string CorrelationId => _httpContextAccessor.HttpContext?.Items["X-Correlation-ID"]?.ToString() ?? "none";

    public async Task<ApiResponse<UserProfileDto>> GetUserProfileAsync(string userId)
    {
        try
        {
            _logger.LogInformation("GetUserProfileAsync started. CorrelationId: {CorrelationId}", CorrelationId);

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogWarning("User not found. UserId: {UserId}", userId);
                return NotFoundErrorResponse<UserProfileDto>("User not found.");
            }

            if (await _userManager.IsLockedOutAsync(user))
            {
                _logger.LogWarning("Locked out user attempted sensitive action. UserId: {UserId}", user.Id);
                return ValidationErrorResponse<UserProfileDto>("Account is locked. Try again later.");
            }


            return GenericSuccessResponse(new UserProfileDto
            {
                Status = OperationStatus.Ok,
                Id = user.Id,
                FirstName = user.FirstName,
                LastName = user.LastName,
                Email = user.Email ?? Empty,
                City = user.City,
                State = user.State
            }, "User profile retrieved.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred in GetUserProfileAsync. CorrelationId: {CorrelationId}", CorrelationId);
            return InternalErrorResponse<UserProfileDto>(ex.Message);
        }
    }

    public async Task<ApiResponse<OperationDto>> RequestPasswordChangeAsync(
        ChangePasswordRequestDto changePasswordRequest)
    {
        try
        {
            _logger.LogInformation("RequestPasswordChange started. CorrelationId: {CorrelationId}", CorrelationId);
            var ip = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            _logger.LogInformation("RequestPasswordChange requested from IP: {IpAddress}", ip);


            var user = await _userManager.FindByIdAsync(changePasswordRequest.UserId);
            if (user == null)
            {
                _logger.LogWarning("User not found for password change request. User Id: {UserId}",
                    changePasswordRequest.UserId);
                return NotFoundErrorResponse<OperationDto>("User not found.");
            }

            if (IsNullOrEmpty(user.Email))
            {
                _logger.LogWarning("User email is not set. UserId: {UserId}", changePasswordRequest.UserId);
                return ValidationErrorResponse<OperationDto>("User email is not set.");
            }

            if (await _userManager.IsLockedOutAsync(user))
            {
                _logger.LogWarning("Locked out user attempted sensitive action. UserId: {UserId}", user.Id);
                return ValidationErrorResponse<OperationDto>("Account is locked. Try again later.");
            }


            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            var link = _urlBuilderService.BuildPasswordChangeUrl(new PasswordChangeRequest()
            {
                UserId = user.Id,
                Email = user.Email,
                Scheme = changePasswordRequest.Scheme,
                Host = changePasswordRequest.Host,
                Token = token,
            });

            await _emailSender.SendPasswordChangeConfirmationAsync(user, new LoginMetadata
            {
                Domain = changePasswordRequest.Host.Value,
                RequestLink = link
            });

            return GenericSuccessResponse(new OperationDto
            {
                Status = OperationStatus.Ok,
                Description = "Password change confirmation sent."
            }, "Password change requested.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred in RequestPasswordChangeAsync. CorrelationId: {CorrelationId}", CorrelationId);
            return InternalErrorResponse<OperationDto>(ex.Message);
        }
    }

    public async Task<ApiResponse<UpdateProfileDto>> UpdateProfileAsync(UpdateProfileRequestDto dto)
    {
        try
        {
            _logger.LogInformation("UpdateProfileAsync started. CorrelationId: {CorrelationId}", CorrelationId);
            var ip = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            _logger.LogInformation("UpdateProfileAsync requested from IP: {IpAddress}", ip);

            var user = await _userManager.FindByIdAsync(dto.UserId);
            if (user == null)
            {
                _logger.LogWarning("User not found for update. UserId: {UserId}", dto.UserId);
                return NotFoundErrorResponse<UpdateProfileDto>("User not found.");
            }

            user.FirstName = dto.FirstName;
            user.LastName = dto.LastName;
            user.City = dto.City;
            user.State = dto.State;

            if (await _userManager.IsLockedOutAsync(user))
            {
                _logger.LogWarning("Locked out user attempted sensitive action. UserId: {UserId}", user.Id);
                return ValidationErrorResponse<UpdateProfileDto>("Account is locked. Try again later.");
            }


            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                _logger.LogError("Failed to update profile for UserId: {UserId}. Errors: {@Errors}", dto.UserId,
                    result.Errors);
                return InternalErrorResponse<UpdateProfileDto>(result.Errors.Select(e => e.Description).ToList());
            }

            return GenericSuccessResponse(new UpdateProfileDto
            {
                Status = OperationStatus.Ok,
                Description = "Profile updated successfully.",
                FirstName = dto.FirstName,
                LastName = dto.LastName,
                Email = dto.Email,
                City = dto.City,
                State = dto.State,
            }, "Profile updated.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred in UpdateProfileAsync. CorrelationId: {CorrelationId}", CorrelationId);
            return InternalErrorResponse<UpdateProfileDto>(ex.Message);
        }
    }

    public async Task<ApiResponse<OperationDto>> ConfirmPasswordChangeAsync(ConfirmPasswordRequestDto dto)
    {
        try
        {
            _logger.LogInformation("ChangePasswordConfirmAsync started. CorrelationId: {CorrelationId}", CorrelationId);
            var ip = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            _logger.LogInformation("ChangePasswordConfirmAsync requested from IP: {IpAddress}", ip);

            var user = await _userManager.FindByIdAsync(dto.UserId);
            if (user == null)
            {
                _logger.LogWarning("User not found. UserId: {UserId}", dto.UserId);
                return NotFoundErrorResponse<OperationDto>("User not found.");
            }

            if (IsNullOrEmpty(dto.Token))
            {
                _logger.LogWarning("Token is missing. UserId: {UserId}", dto.UserId);
                return ValidationErrorResponse<OperationDto>("Reset token is required.");
            }

            if (await _userManager.IsLockedOutAsync(user))
            {
                _logger.LogWarning("Locked out user attempted sensitive action. UserId: {UserId}", user.Id);
                return ValidationErrorResponse<OperationDto>("Account is locked. Try again later.");
            }


            var result = await _userManager.ResetPasswordAsync(user, dto.Token, dto.NewPassword);

            if (!result.Succeeded)
            {
                _logger.LogError("Password reset failed for UserId: {UserId}. Errors: {@Errors}", dto.UserId,
                    result.Errors);
                return ValidationErrorResponse<OperationDto>("Password reset failed.",
                    result.Errors.Select(e => e.Description).ToList());
            }

            return GenericSuccessResponse(new OperationDto
            {
                Status = OperationStatus.Ok,
                Description = "Password changed successfully."
            }, "Password reset successful.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred in ConfirmPasswordChangeAsync. CorrelationId: {CorrelationId}", CorrelationId);
            return InternalErrorResponse<OperationDto>(ex.Message);
        }
    }   
    
    public async Task<ApiResponse<OperationDto>> RequestEmailChangeAsync(ChangeEmailRequestDto dto)
    {
        try
        {
            _logger.LogInformation("RequestEmailChangeAsync started. CorrelationId: {CorrelationId}", CorrelationId);
            var ip = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            _logger.LogInformation("RequestEmailChangeAsync change requested from IP: {IpAddress}", ip);


            var user = await _userManager.FindByIdAsync(dto.UserId);
            if (user == null)
            {
                _logger.LogWarning("User not found for email change request. UserId: {UserId}", dto.UserId);
                return NotFoundErrorResponse<OperationDto>("User not found.");
            }

            if (await _userManager.IsLockedOutAsync(user))
            {
                _logger.LogWarning("Locked out user attempted sensitive action. UserId: {UserId}", user.Id);
                return ValidationErrorResponse<OperationDto>("Account is locked. Try again later.");
            }

            var token = await _userManager.GenerateChangeEmailTokenAsync(user, dto.NewEmail);

            var emailChangeRequest = new EmailChangeRequest()
            {
                UserId = user.Id,
                NewEmail = dto.NewEmail,
                Scheme = dto.Scheme,
                Host = dto.Host,
                Token = token,
            };

            var link = _urlBuilderService.BuildEmailChangeCallbackUrl(emailChangeRequest);

            await _emailSender.SendEmailChangeConfirmationAsync(user, link);

            return GenericSuccessResponse(new OperationDto
            {
                Status = OperationStatus.Ok,
                Description = "Email change confirmation sent."
            }, "Email change requested.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred in RequestEmailChangeAsync. CorrelationId: {CorrelationId}", CorrelationId);
            return InternalErrorResponse<OperationDto>(ex.Message);
        }
    }

    public async Task<ApiResponse<OperationDto>> ConfirmEmailChangeAsync(ConfirmEmailRequestDto dto)
    {
        try
        {
            _logger.LogInformation("ConfirmEmailChangeAsync started. CorrelationId: {CorrelationId}", CorrelationId);
            var ip = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            _logger.LogInformation("ConfirmEmailChangeAsync requested from IP: {IpAddress}", ip);

            var user = await _userManager.FindByIdAsync(dto.UserId);
            if (user == null)
            {
                _logger.LogWarning("User not found for confirming email change. UserId: {UserId}", dto.UserId);
                return NotFoundErrorResponse<OperationDto>("User not found.");
            }

            if (await _userManager.IsLockedOutAsync(user))
            {
                _logger.LogWarning("Locked out user attempted sensitive action. UserId: {UserId}", user.Id);
                return ValidationErrorResponse<OperationDto>("Account is locked. Try again later.");
            }

            var result = await _userManager.ChangeEmailAsync(user, dto.NewEmail, dto.Token);
            if (!result.Succeeded)
            {
                _logger.LogError("Email change confirmation failed. UserId: {UserId}. Errors: {@Errors}", dto.UserId,
                    result.Errors);
                return InternalErrorResponse<OperationDto>(
                    result.Errors.Select(e => e.Description).ToList());
            }

            return GenericSuccessResponse(new OperationDto
            {
                Status = OperationStatus.Ok,
                Description = "Email successfully updated."
            }, "Email change confirmed.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred in ConfirmEmailChangeAsync. CorrelationId: {CorrelationId}", CorrelationId);
            return InternalErrorResponse<OperationDto>(ex.Message);
        }
    }
    
    public async Task<ApiResponse<OperationDto>> DeleteAccountAsync(DeleteAccountRequestDto dto)
    {
        try
        {
            _logger.LogInformation("DeleteAccountAsync started. CorrelationId: {CorrelationId}", CorrelationId);
            var ip = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            _logger.LogInformation("DeleteAccountAsync requested from IP: {IpAddress}", ip);

            var user = await _userManager.FindByIdAsync(dto.UserId);
            if (user == null)
            {
                _logger.LogWarning("User not found for deletion. UserId: {UserId}", dto.UserId);
                return NotFoundErrorResponse<OperationDto>("User not found.");
            }

            if (!dto.Confirm)
            {
                _logger.LogWarning("Account deletion not confirmed. UserId: {UserId}", dto.UserId);
                return ValidationErrorResponse<OperationDto>("Account deletion not confirmed.");
            }

            if (await _userManager.IsLockedOutAsync(user))
            {
                _logger.LogWarning("Locked out user attempted sensitive action. UserId: {UserId}", user.Id);
                return ValidationErrorResponse<OperationDto>("Account is locked. Try again later.");
            }

            var result = await _userManager.DeleteAsync(user);
            if (!result.Succeeded)
            {
                _logger.LogError("Failed to delete user. UserId: {UserId}. Errors: {@Errors}", dto.UserId,
                    result.Errors);
                return InternalErrorResponse<OperationDto>(
                    result.Errors.Select(e => e.Description).ToList());
            }

            return GenericSuccessResponse(new OperationDto
            {
                Status = OperationStatus.Ok,
                Description = "Account deleted."
            }, "Account deleted.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred in DeleteAccountAsync. CorrelationId: {CorrelationId}", CorrelationId);
            return InternalErrorResponse<OperationDto>(ex.Message);
        }
    }

    public async Task<ApiResponse<ToggleTwoFactorDto>> ToggleTwoFactorAsync(ToggleTwoFactorRequestDto dto)
    {
        try
        {
            _logger.LogInformation("ToggleTwoFactorAsync started. CorrelationId: {CorrelationId}", CorrelationId);
            var ip = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            _logger.LogInformation("ToggleTwoFactorAsync requested from IP: {IpAddress}", ip);


            var user = await _userManager.FindByIdAsync(dto.UserId);
            if (user == null)
            {
                _logger.LogWarning("User not found for toggling 2FA. UserId: {UserId}", dto.UserId);
                return NotFoundErrorResponse<ToggleTwoFactorDto>("User not found.");
            }

            if (await _userManager.IsLockedOutAsync(user))
            {
                _logger.LogWarning("Locked out user attempted sensitive action. UserId: {UserId}", user.Id);
                return ValidationErrorResponse<ToggleTwoFactorDto>("Account is locked. Try again later.");
            }

            var result = await _userManager.SetTwoFactorEnabledAsync(user, dto.IsEnabled);
            if (!result.Succeeded)
            {
                _logger.LogError("Failed to toggle 2FA. UserId: {UserId}. Errors: {@Errors}", dto.UserId,
                    result.Errors);
                return InternalErrorResponse<ToggleTwoFactorDto>(result.Errors.Select(e => e.Description).ToList());
            }

            return GenericSuccessResponse(new ToggleTwoFactorDto
            {
                Status = OperationStatus.Ok,
                Description = dto.IsEnabled ? "2FA enabled." : "2FA disabled.",
                IsEnabled = dto.IsEnabled
            }, "Two-factor authentication updated.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred in ToggleTwoFactorAsync. CorrelationId: {CorrelationId}", CorrelationId);
            return InternalErrorResponse<ToggleTwoFactorDto>(ex.Message);
        }
    }
    
    public async Task<ApplicationUser> GetUserByIdAsync(string userId)
    {
        try
        {
            _logger.LogInformation("GetUserByIdAsync started. CorrelationId: {CorrelationId}", CorrelationId);
            var ip = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            _logger.LogInformation("GetUserByIdAsync requested from IP: {IpAddress}", ip);

            var user = await _userManager.FindByIdAsync(userId);
            
            return user!;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred in GetUserByIdAsync. CorrelationId: {CorrelationId}", CorrelationId);
            throw;
        }
    }

    private ApiResponse<T> GenericSuccessResponse<T>(T data, string message) where T : BaseOperationDto => new()
    {
        Success = true,
        Message = message,
        Data = data
    };

    private ApiResponse<T> NotFoundErrorResponse<T>(string message) => new()
    {
        Success = false,
        Message = message,
        Error = new ApiError
        {
            Status = OperationStatus.Error,
            Code = "NOT_FOUND",
            Category = ErrorCategory.NotFound,
            Description = "The resource you're trying to access was not found.",
            Errors = new List<string> { message }
        }
    };

    private ApiResponse<T> ValidationErrorResponse<T>(string message) => new()
    {
        Success = false,
        Message = message,
        Error = new ApiError
        {
            Status = OperationStatus.Error,
            Code = "VALIDATION_ERROR",
            Category = ErrorCategory.Validation,
            Description = "Some fields contain invalid or missing values.",
            Errors = new List<string> { message }
        }
    };

    private ApiResponse<T> ValidationErrorResponse<T>(string message, List<string> errors) => new()
    {
        Success = false,
        Message = message,
        Error = new ApiError
        {
            Status = OperationStatus.Error,
            Code = "VALIDATION_ERROR",
            Category = ErrorCategory.Validation,
            Description = "Some fields contain invalid or missing values.",
            Errors = errors
        }
    };
    
    private ApiResponse<T> InternalErrorResponse<T>(string errors) => new()
    {
        Success = false,
        Message = "An internal error occurred. Please try again later.",
        Error = new ApiError
        {
            Status = OperationStatus.Error,
            Code = "INTERNAL_ERROR",
            Category = ErrorCategory.Internal,
            Description =
                "The server encountered an unexpected condition that prevented it from fulfilling the request.",
            Errors = new List<string> { errors }
        }
    };
    
    private ApiResponse<T> InternalErrorResponse<T>(List<string> errors) => new()
    {
        Success = false,
        Message = "An internal error occurred. Please try again later.",
        Error = new ApiError
        {
            Status = OperationStatus.Error,
            Code = "INTERNAL_ERROR",
            Category = ErrorCategory.Internal,
            Description = "The server encountered an unexpected condition that prevented it from fulfilling the request.",
            Errors = errors
        }
    };
}