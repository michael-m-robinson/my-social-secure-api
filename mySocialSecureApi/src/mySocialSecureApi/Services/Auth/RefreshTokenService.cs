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

    public RefreshTokenService(
        ApplicationDbContext dbContext,
        ILogger<RefreshTokenService> logger,
        IOptions<JwtSettings> jwtSettings,
        IHttpContextAccessor httpContextAccessor)
    {
        _dbContext = dbContext;
        _logger = logger;
        _jwtSettings = jwtSettings.Value ?? throw new ArgumentNullException(nameof(jwtSettings));
        _httpContextAccessor = httpContextAccessor;
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
                ExpiresUtc = refreshToken.ExpiresUtc
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

    public async Task<ApiResponse<TokenDto>> GetValidTokenAsync(string token)
    {
        try
        {
            _logger.LogInformation("GetValidTokenAsync started. CorrelationId: {CorrelationId}", CorrelationId);
            var ip = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            _logger.LogInformation("GetValidTokenAsync requested from IP: {IpAddress}", ip);
            if (string.IsNullOrWhiteSpace(token))
            {
                _logger.LogWarning("Empty token passed to GetValidTokenAsync.");
                return BuildErrorResponse<TokenDto>("Token cannot be null or empty.", "INVALID_TOKEN", ErrorCategory.Authentication);
            }

            var validToken = await _dbContext.RefreshTokens
                .Include(rt => rt.User)
                .FirstOrDefaultAsync(rt => rt.Token == token && !rt.IsRevoked && rt.ExpiresUtc > DateTime.UtcNow);

            if (validToken == null)
            {
                _logger.LogWarning("Invalid or expired refresh token.");
                return BuildErrorResponse<TokenDto>("Invalid refresh token.", "INVALID_TOKEN", ErrorCategory.Authentication);
            }

            return BuildSuccessResponse(new TokenDto
            {
                Status = OperationStatus.Ok,
                Token = validToken.Token,
                ExpiresUtc = validToken.ExpiresUtc
            }, "The refresh token is valid.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving refresh token. CorrelationId: {CorrelationId}", CorrelationId);
            return BuildErrorResponse<TokenDto>(
                "Failed to validate refresh token.",
                "TOKEN_RETRIEVAL_FAILED",
                ErrorCategory.Internal);
        }
    }

    public async Task RevokeTokenAsync(string token)
    {
        _logger.LogInformation("GetValidTokenAsync started. CorrelationId: {CorrelationId}", CorrelationId);
        var ip = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        _logger.LogInformation("GetValidTokenAsync requested from IP: {IpAddress}", ip);

        try
        {
            var storedToken = await _dbContext.RefreshTokens.FirstOrDefaultAsync(rt => rt.Token == token);

            if (storedToken != null)
            {
                storedToken.IsRevoked = true;
                await _dbContext.SaveChangesAsync();
                _logger.LogInformation("Refresh token revoked: {Token}", token);
            }
            else
            {
                _logger.LogWarning("Token not found for revocation: {Token}", token);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error revoking token. CorrelationId: {CorrelationId}", CorrelationId);
            throw;
        }
    }

    public async Task<ApiResponse<OperationDto>> ValidateRefreshTokenAsync(string refreshToken)
    {
        _logger.LogInformation("ValidateRefreshTokenAsync started. CorrelationId: {CorrelationId}", CorrelationId);
        var ip = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        _logger.LogInformation("ValidateRefreshTokenAsync requested from IP: {IpAddress}", ip);

        try
        {
            if (string.IsNullOrEmpty(refreshToken))
            {
                _logger.LogWarning("Null or empty refresh token.");
                return BuildErrorResponse<OperationDto>("Token cannot be null or empty.", "INVALID_TOKEN", ErrorCategory.Authentication);
            }

            var storedToken = await _dbContext.RefreshTokens
                .Include(x => x.User)
                .FirstOrDefaultAsync(x => x.Token == refreshToken && !x.IsRevoked && x.ExpiresUtc > DateTime.UtcNow);

            if (storedToken == null)
            {
                _logger.LogWarning("Refresh token not found or expired.");
                return BuildErrorResponse<OperationDto>("Invalid refresh token.", "INVALID_TOKEN", ErrorCategory.Authentication);
            }

            return BuildSuccessResponse(new OperationDto
            {
                Status = OperationStatus.Ok,
                Description = "Refresh token is valid."
            }, "Refresh token validated.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating refresh token. CorrelationId: {CorrelationId}", CorrelationId);
            return BuildErrorResponse<OperationDto>(
                "Failed to validate refresh token.",
                "TOKEN_VALIDATION_FAILED",
                ErrorCategory.Internal);
        }
    }

    // === Helpers ===

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
