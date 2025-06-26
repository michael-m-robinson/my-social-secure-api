using My_Social_Secure_Api.Enums.Common;
using My_Social_Secure_Api.Interfaces.Services.Auth;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Auth;
using My_Social_Secure_Api.Models.Identity;

namespace My_Social_Secure_Api.Services.Auth;

public class TokenBundleService(
    IJwtTokenGenerator jwtTokenGenerator,
    IRefreshTokenService refreshTokenService)
{
    public async Task<ApiResponse<TokenBundleDto>> IssueTokenBundleAsync(ApplicationUser user)
    {
        var accessToken = jwtTokenGenerator.GenerateToken(user);

        // Handle 'Bearer ' prefix defensively
        var tokenOnly = accessToken.StartsWith("Bearer ") ? accessToken["Bearer ".Length..] : accessToken;
        jwtTokenGenerator.ValidateToken(tokenOnly, out var utc);

        var refreshResult = await refreshTokenService.CreateRefreshTokenAsync(user);
        if (!refreshResult.Success)
            return ApiResponse<TokenBundleDto>.FromError(refreshResult.Error!); // Ensure this exists

        utc ??= DateTime.UtcNow.AddMinutes(15);

        return new ApiResponse<TokenBundleDto>
        {
            Success = true,
            Message = "Token bundle issued successfully.",
            Data = new TokenBundleDto
            {
                Status = OperationStatus.Ok,
                AccessToken = accessToken,
                AccessTokenExpiresUtc = utc.Value,
                RefreshToken = refreshResult.Data!.Token,
                RefreshTokenExpiresUtc = refreshResult.Data.ExpiresUtc
            }
        };
    }
}
