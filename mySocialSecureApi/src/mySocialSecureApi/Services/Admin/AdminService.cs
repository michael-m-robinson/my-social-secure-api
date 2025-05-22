using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using My_Social_Secure_Api.Data;
using My_Social_Secure_Api.Enums.Common;
using My_Social_Secure_Api.Interfaces.Services.Admin;
using My_Social_Secure_Api.Interfaces.Services.DeviceRecognition;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Admin;
using My_Social_Secure_Api.Models.Dtos.Common;
using My_Social_Secure_Api.Models.Dtos.LoginTracking;
using My_Social_Secure_Api.Models.Dtos.Notifications;
using My_Social_Secure_Api.Models.Identity;

// ReSharper disable ConvertToPrimaryConstructor

namespace My_Social_Secure_Api.Services.Admin;

public class AdminService : IAdminService
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<AdminService> _logger;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IDeviceRecognitionService _deviceRecognitionService;

    public AdminService(
        ApplicationDbContext context,
        UserManager<ApplicationUser> userManager,
        ILogger<AdminService> logger,
        IDeviceRecognitionService deviceRecognitionService,
        IHttpContextAccessor httpContextAccessor)
    {
        _context = context;
        _userManager = userManager;
        _logger = logger;
        _httpContextAccessor = httpContextAccessor;
        _deviceRecognitionService = deviceRecognitionService;
    }

    public async Task<ApiResponse<UserListDto>> GetAllUsersAsync()
    {
        var correlationId = _httpContextAccessor.HttpContext?.Items["X-Correlation-ID"]?.ToString();
        _logger.LogInformation("GetAllUsersAsync started. CorrelationId: {CorrelationId}", correlationId);

        try
        {
            var users = await _context.Users
                .AsNoTracking()
                .Select(u => new UserDto
                {
                    Status = OperationStatus.Ok,
                    Id = u.Id,
                    Email = u.Email!,
                    UserName = u.UserName!,
                    FirstName = u.FirstName
                })
                .ToListAsync();

            var userList = new UserListDto
            {
                Status = OperationStatus.Ok,
                Description = "Users retrieved successfully.",
                Users = users
            };

            return GenericSuccessResponse(userList, "Users fetched successfully.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred while fetching all users.");
            return InternalErrorResponse<UserListDto>();
        }
    }

    public async Task<ApiResponse<UserActionDto>> GetUserByIdAsync(string userId)
    {
        var correlationId = _httpContextAccessor.HttpContext?.Items["X-Correlation-ID"]?.ToString();
        _logger.LogInformation("GetUserByIdAsync started. CorrelationId: {CorrelationId}", correlationId);

        try
        {
            var user = await _context.Users
                .AsNoTracking()
                .FirstOrDefaultAsync(u => u.Id == userId);

            if (user == null)
            {
                _logger.LogWarning("User with ID {UserId} not found.", userId);
                return NotFoundErrorResponse<UserActionDto>("User not found.");
            }

            var userAction = new UserActionDto
            {
                Status = OperationStatus.Ok,
                Description = "User retrieved successfully.",
                UserId = user.Id,
                UserName = user.UserName!,
                Email = user.Email!,
            };

            return GenericSuccessResponse(userAction, "User fetched successfully.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred while fetching user by ID {UserId}.", userId);
            return InternalErrorResponse<UserActionDto>();
        }
    }

    public async Task<ApiResponse<UserActionDto>> UpdateUserAsync(string userId, UpdateUserDto dto)
    {
        var correlationId = _httpContextAccessor.HttpContext?.Items["X-Correlation-ID"]?.ToString();
        _logger.LogInformation("UpdateUserAsync started. CorrelationId: {CorrelationId}", correlationId);

        try
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogWarning("User with ID {UserId} not found for update.", userId);
                return NotFoundErrorResponse<UserActionDto>("User not found.");
            }

            user.UserName = dto.UserName;
            user.Email = dto.Email;
            user.FirstName = dto.FirstName;
            user.LastName = dto.LastName;

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                _logger.LogWarning("Failed to update user {UserId}. Errors: {@Errors}", user.Id, result.Errors);
                return GenericErrorResponse<UserActionDto>("Failed to update the user.");
            }

            var updatedUser = new UserActionDto
            {
                Status = OperationStatus.Ok,
                Description = "User updated successfully.",
                UserId = user.Id,
                UserName = user.UserName!,
                Email = user.Email!,
            };

            return GenericSuccessResponse(updatedUser, "User updated successfully.");
        }
        catch (DbUpdateException dbEx)
        {
            _logger.LogError(dbEx, "Database update failed.");
            return DatabaseErrorResponse<UserActionDto>("Database update failed.");
        }
        catch (UnauthorizedAccessException uaEx)
        {
            _logger.LogWarning(uaEx, "Unauthorized access attempt.");
            return UnauthorizedErrorResponse<UserActionDto>();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred while updating user with ID {UserId}.", userId);
            return InternalErrorResponse<UserActionDto>();
        }
    }

    public async Task<ApiResponse<OperationDto>> AssignRoleAsync(RoleAssignmentRequestDto requestDto)
    {
        var correlationId = _httpContextAccessor.HttpContext?.Items["X-Correlation-ID"]?.ToString();
        _logger.LogInformation("AssignRoleAsync started. CorrelationId: {CorrelationId}", correlationId);

        try
        {
            var user = await _userManager.FindByIdAsync(requestDto.UserId);
            if (user == null)
            {
                _logger.LogWarning("User with ID {UserId} not found for role assignment.", requestDto.UserId);
                return NotFoundErrorResponse<OperationDto>("User not found.");
            }

            if (await _userManager.IsInRoleAsync(user, requestDto.RoleName))
            {
                _logger.LogWarning("User with ID {UserId} already has role {Role}.", requestDto.UserId, requestDto.RoleName);
                return ValidationErrorResponse<OperationDto>("User already has this role.");
            }

            var result = await _userManager.AddToRoleAsync(user, requestDto.RoleName);
            if (!result.Succeeded)
            {
                _logger.LogWarning("Failed to assign role {Role} to user {UserId}. Errors: {@Errors}", requestDto.RoleName, requestDto.UserId,
                    result.Errors);
                return ValidationErrorResponse<OperationDto>("Failed to assign the role.");
            }

            var roleData = new OperationDto
            {
                Status = OperationStatus.Ok,
                Description = "Role assigned successfully."
            };

            return GenericSuccessResponse(roleData, "Role assigned successfully.");
        }
        catch (DbUpdateException dbEx)
        {
            _logger.LogError(dbEx, "Database update failed.");
            return DatabaseErrorResponse<OperationDto>("Database update failed.");
        }
        catch (UnauthorizedAccessException uaEx)
        {
            _logger.LogWarning(uaEx, "Unauthorized access attempt.");
            return UnauthorizedErrorResponse<OperationDto>();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred while assigning role {Role} to user {UserId}.", requestDto.RoleName, requestDto.UserId);
            return InternalErrorResponse<OperationDto>();
        }
    }

    public async Task<ApiResponse<OperationDto>> RemoveRoleAsync(RoleRemovalRequestDto dto)
    {
        var correlationId = _httpContextAccessor.HttpContext?.Items["X-Correlation-ID"]?.ToString();
        _logger.LogInformation("RemoveRoleAsync started. CorrelationId: {CorrelationId}", correlationId);

        try
        {
            var user = await _userManager.FindByIdAsync(dto.UserId);
            if (user == null)
            {
                _logger.LogWarning("User with ID {UserId} not found for role removal.", dto.UserId);
                return NotFoundErrorResponse<OperationDto>("User not found.");
            }

            var result = await _userManager.RemoveFromRoleAsync(user, dto.RoleName);
            if (!result.Succeeded)
            {
                _logger.LogWarning("Failed to remove role {Role} from user {UserId}. Errors: {@Errors}", dto.RoleName, dto.UserId,
                    result.Errors);
                return ValidationErrorResponse<OperationDto>("Failed to remove the role.");
            }

            var roleData = new OperationDto
            {
                Status = OperationStatus.Ok,
                Description = "Role removed successfully."
            };

            return GenericSuccessResponse(roleData, "Role removed successfully.");
        }
        catch (DbUpdateException dbEx)
        {
            _logger.LogError(dbEx, "Database update failed.");
            return DatabaseErrorResponse<OperationDto>("Database update failed.");
        }
        catch (UnauthorizedAccessException uaEx)
        {
            _logger.LogWarning(uaEx, "Unauthorized access attempt.");
            return UnauthorizedErrorResponse<OperationDto>();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred while removing role {Role} from user {UserId}.", dto.RoleName, dto.UserId);
            return InternalErrorResponse<OperationDto>();
        }
    }

    public async Task<ApiResponse<RoleListDto>> GetUserRolesAsync(string userId)
    {
        var correlationId = _httpContextAccessor.HttpContext?.Items["X-Correlation-ID"]?.ToString();
        _logger.LogInformation("GetUserRolesAsync started. CorrelationId: {CorrelationId}", correlationId);

        try
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogWarning("User with ID {UserId} not found for fetching roles.", userId);
                return NotFoundErrorResponse<RoleListDto>("User not found.");
            }

            var roles = await _userManager.GetRolesAsync(user);
            var roleList = new RoleListDto
            {
                Status = OperationStatus.Ok,
                Description = "User roles fetched successfully.",
                Roles = roles.ToList()
            };

            return GenericSuccessResponse(roleList, "User roles fetched successfully.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred while fetching roles for user {UserId}.", userId);
            return InternalErrorResponse<RoleListDto>();
        }
    }

    public async Task<ApiResponse<LoginHistoryListDto>> GetUserLoginHistoryAsync(string userId)
    {
        var correlationId = _httpContextAccessor.HttpContext?.Items["X-Correlation-ID"]?.ToString();
        _logger.LogInformation("GetUserLoginHistoryAsync started. CorrelationId: {CorrelationId}", correlationId);

        try
        {
            var loginHistories = await _context.LoginHistories
                .AsNoTracking()
                .Where(x => x.UserId == userId)
                .OrderByDescending(x => x.LoginTimeUtc)
                .Select(x => new LoginHistoryDto
                {
                    Status = OperationStatus.Ok,
                    IpAddress = x.IpAddress,
                    Device = x.Device,
                    Location = x.Location,
                    LoginTimeUtc = x.LoginTimeUtc
                })
                .ToListAsync();

            var loginHistoryList = new LoginHistoryListDto
            {
                Status = OperationStatus.Ok,
                Description = "Login history fetched successfully.",
                LoginHistories = loginHistories
            };

            return GenericSuccessResponse(loginHistoryList, "Login history fetched successfully.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred while fetching login history for user {UserId}.", userId);
            return InternalErrorResponse<LoginHistoryListDto>();
        }
    }

    public async Task<ApiResponse<LoginAlertListDto>> GetTopTenUserLoginAlertsAsync(string userId, int count = 10)
    {
        var correlationId = _httpContextAccessor.HttpContext?.Items["X-Correlation-ID"]?.ToString();
        _logger.LogInformation("GetTopTenUserLoginAlertsAsync started. CorrelationId: {CorrelationId}", correlationId);
        var ip = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        _logger.LogInformation("GetTopTenUserLoginAlertsAsync requested from IP: {IpAddress}", ip);

        try
        {
            var alerts = await _context.LoginAlerts
                .AsNoTracking()
                .Where(a => a.UserId == userId)
                .OrderByDescending(a => a.LoginTime)
                .Take(count)
                .ToListAsync();

            var loginAlerts = alerts.Select(alert => new LoginAlertDto
            {
                IpAddress = alert.IpAddress,
                Location = alert.Location,
                LoginTime = alert.LoginTime.ToString("u"),
                DeviceSummary = _deviceRecognitionService.GetDeviceSummary(alert.UserAgent)
            }).ToList();

            return new ApiResponse<LoginAlertListDto>
            {
                Success = true,
                Data = new LoginAlertListDto
                {
                    Status = OperationStatus.Ok,
                    Description = "Top 10 login alerts fetched successfully.",
                    LoginAlerts = loginAlerts
                },
                Message = "Top 10 login alerts fetched successfully."
            };
        }
        catch (UnauthorizedAccessException uaEx)
        {
            _logger.LogWarning(uaEx, "Unauthorized access attempt while fetching recent login alerts. Correlation ID: {CorrelationId}", correlationId);
            return UnauthorizedErrorResponse<LoginAlertListDto>();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while fetching recent login alerts for user {UserId} Correlation ID: {CorrelationId}.", userId, correlationId);
            return InternalErrorResponse<LoginAlertListDto>();
        }
    }

    private ApiResponse<T> GenericSuccessResponse<T>(T data, string message)
    {
        return new ApiResponse<T>
        {
            Success = true,
            Data = data,
            Message = message
        };
    }

    private ApiResponse<T> GenericErrorResponse<T>(string message)
    {
        return new ApiResponse<T>
        {
            Success = false,
            Message = message,
            Error = new ApiError
            {
                Status = OperationStatus.Error,
                Description =
                    "The request could not be completed due to an unexpected error. Please review the error details and try again.",
                Code = "INVALID_REQUEST",
                Category = ErrorCategory.Validation,
                Errors = new List<string> { message }
            }
        };
    }

    private ApiResponse<T> DatabaseErrorResponse<T>(string message)
    {
        return new ApiResponse<T>
        {
            Success = false,
            Message = message,
            Error = new ApiError
            {
                Status = OperationStatus.Error,
                Description = "The request could not be completed due to a database error.",
                Code = "DATABASE_ERROR",
                Category = ErrorCategory.Internal,
                Errors = new List<string> { message }
            }
        };
    }

    private ApiResponse<T> NotFoundErrorResponse<T>(string message)
    {
        return new ApiResponse<T>
        {
            Success = false,
            Message = message,
            Error = new ApiError
            {
                Status = OperationStatus.Error,
                Description = "The resource you're trying to access was not found.",
                Code = "NOT_FOUND",
                Category = ErrorCategory.NotFound,
                Errors = new List<string> { message }
            }
        };
    }

    private ApiResponse<T> ValidationErrorResponse<T>(string message)
    {
        return new ApiResponse<T>
        {
            Success = false,
            Message = message,
            Error = new ApiError
            {
                Status = OperationStatus.Error,
                Description = "Some fields contain invalid or missing values.",
                Code = "VALIDATION_ERROR",
                Category = ErrorCategory.Validation,
                Errors = new List<string> { message }
            }
        };
    }

    private ApiResponse<T> InternalErrorResponse<T>()
    {
        return new ApiResponse<T>
        {
            Success = false,
            Message = "An internal error occurred. Please try again later.",
            Error = new ApiError
            {
                Status = OperationStatus.Error,
                Description =
                    "The server encountered an unexpected condition that prevented it from fulfilling the request.",
                Code = "INTERNAL_ERROR",
                Category = ErrorCategory.Internal,
                Errors = new List<string> { "A server error has occurred." }
            }
        };
    }

    private ApiResponse<T> UnauthorizedErrorResponse<T>()
    {
        return new ApiResponse<T>
        {
            Success = false,
            Message = "Access denied.",
            Error = new ApiError
            {
                Status = OperationStatus.Failed,
                Description = "You do not have permission to access this resource.",
                Code = "UNAUTHORIZED_ACCESS",
                Category = ErrorCategory.Authorization,
                Errors = new List<string> { "Access denied." }
            }
        };
    }
}