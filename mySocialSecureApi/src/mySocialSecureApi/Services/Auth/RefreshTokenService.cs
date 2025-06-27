using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using My_Social_Secure_Api.Data;
using My_Social_Secure_Api.Enums.Common;
using My_Social_Secure_Api.Interfaces.Services.Auth;
using My_Social_Secure_Api.Models.Auth;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Auth;
using My_Social_Secure_Api.Models.Dtos.Common;
using My_Social_Secure_Api.Models.Identity;

// ReSharper disable ConvertToPrimaryConstructor

namespace My_Social_Secure_Api.Services.Auth;

public class RefreshTokenService : IRefreshTokenService
{
    private readonly ApplicationDbContext _dbContext;
    private readonly ILogger<RefreshTokenService> _logger;
    private readonly JwtSettings _jwtSettings;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IJwtTokenGenerator _jwtTokenGenerator;

    public RefreshTokenService(
        ApplicationDbContext dbContext,
        ILogger<RefreshTokenService> logger,
        IOptions<JwtSettings> jwtSettings,
        IHttpContextAccessor httpContextAccessor, IJwtTokenGenerator jwtTokenGenerator)
    {
        _dbContext = dbContext;
        _logger = logger;
        _jwtSettings = jwtSettings.Value ?? throw new ArgumentNullException(nameof(jwtSettings));
        _httpContextAccessor = httpContextAccessor;
        _jwtTokenGenerator = jwtTokenGenerator;
    }

    private string CorrelationId =>
        _httpContextAccessor?.HttpContext?.Items["X-Correlation-ID"]?.ToString() ?? "none";

    public async Task<ApiResponse<TokenDto>> CreateRefreshTokenAsync(ApplicationUser user)
    {
        try
        {
            _logger.LogInformation("CreateRefreshTokenAsync started. CorrelationId: {CorrelationId}", CorrelationId);
            var ip = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            _logger.LogInformation("TCreateRefreshTokenAsync requested from IP: {IpAddress}", ip);

            var token = GenerateSecureToken();
            var refreshToken = new RefreshTokenModel
            {
                Token = token,
                UserId = user.Id,
                ExpiresUtc = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpireMinutes)
            };

            await _dbContext.RefreshTokens.AddAsync(refreshToken);
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Refresh token created for user ID {UserId}.", user.Id);

            return BuildSuccessResponse(new TokenDto
            {
                Status = OperationStatus.Ok,
                Description = "A new refresh token has been generated successfully.",
                Token = refreshToken.Token,
                RefreshTokenExpiresUtc = refreshToken.ExpiresUtc
            }, "Refresh token created successfully.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating refresh token. CorrelationId: {CorrelationId}", CorrelationId);
            return BuildErrorResponse<TokenDto>(
                "Failed to create refresh token.",
                "TOKEN_CREATION_FAILED",
                ErrorCategory.Internal);
        }
    }

    public async Task<ApiResponse<TokenDto>> ValidateAndRotateRefreshTokenAsync(string refreshToken)
    {
        _logger.LogInformation("ValidateAndRotateRefreshTokenAsync started. CorrelationId: {CorrelationId}",
            CorrelationId);
        var ip = _httpContextAccessor.HttpContext?.Connection?.RemoteIpAddress?.ToString() ?? "unknown";
        _logger.LogInformation("ValidateAndRotateRefreshTokenAsync requested from IP: {IpAddress}", ip);

        try
        {
            if (string.IsNullOrEmpty(refreshToken))
            {
                _logger.LogWarning("Null or empty refresh token.");
                return BuildErrorResponse<TokenDto>(
                    "Token cannot be null or empty.",
                    "INVALID_REFRESH_TOKEN",
                    ErrorCategory.Authentication);
            }

            var storedToken = await _dbContext.RefreshTokens
                .Include(x => x.User)
                .FirstOrDefaultAsync(x =>
                    x.Token == refreshToken && !x.IsRevoked && x.ExpiresUtc > DateTime.UtcNow);

            if (storedToken == null)
            {
                _logger.LogWarning("Refresh token not found or already revoked/expired.");
                return BuildErrorResponse<TokenDto>(
                    "Invalid or already used refresh token.",
                    "INVALID_REFRESH_TOKEN",
                    ErrorCategory.Authentication);
            }

            var user = storedToken.User;

            // Revoke the old token
            storedToken.IsRevoked = true;

            // Issue a new refresh token
            var newToken = GenerateSecureToken();
            
            var newRefreshToken = new RefreshTokenModel
            {
                Token = newToken,
                UserId = storedToken.UserId,
                ExpiresUtc = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpireMinutes)
            };
            await _dbContext.RefreshTokens.AddAsync(newRefreshToken);
            
            await _dbContext.TokenRotationLogs.AddAsync(new TokenRotationLogModel
            {
                OldToken = refreshToken,
                NewToken = newToken,
                UserId = storedToken.UserId,
                IpAddress = ip
            });

            // Generate new access token (JWT)
            var accessToken = _jwtTokenGenerator.GenerateToken(user);

            await _dbContext.SaveChangesAsync();

            return BuildSuccessResponse(new TokenDto
            {
                Status = OperationStatus.Ok,
                Description = "Access and refresh token pair issued successfully.",
                AccessToken = accessToken,
                AccessTokenExpiresUtc = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessExpireMinutes),
                RefreshToken = newRefreshToken.Token,
                RefreshTokenExpiresUtc = newRefreshToken.ExpiresUtc
            }, "Token rotation completed.");

        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error rotating refresh token. CorrelationId: {CorrelationId}", CorrelationId);
            return BuildErrorResponse<TokenDto>(
                "Failed to rotate refresh token.",
                "TOKEN_ROTATION_FAILED",
                ErrorCategory.Internal);
        }
    }


    private static string GenerateSecureToken()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
    }

    private ApiResponse<T> BuildSuccessResponse<T>(T data, string message) where T : BaseOperationDto => new()
    {
        Success = true,
        Message = message,
        Data = data
    };

    private ApiResponse<T> BuildErrorResponse<T>(string message, string errorCode, ErrorCategory category) => new()
    {
        Success = false,
        Message = message,
        Error = new ApiError
        {
            Status = OperationStatus.Error,
            Description = "The request failed due to an error. See details.",
            Code = errorCode,
            Category = category,
            Errors = new List<string> { message }
        }
    };
}