using My_Social_Secure_Api.Enums.Common;
using My_Social_Secure_Api.Interfaces.Services.Auth;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Auth;
using My_Social_Secure_Api.Models.Identity;
using Newtonsoft.Json.Linq;

namespace My_Social_Secure_Api.Services.Auth;

public class TokenBundleService(
    IJwtTokenGenerator jwtTokenGenerator,
    IRefreshTokenService refreshTokenService): ITokenBundleService
{
    public async Task<ApiResponse<TokenBundleDto>> IssueTokenBundleAsync(ApplicationUser user)
    {
        var accessToken = await jwtTokenGenerator.GenerateToken(user);

        // Handle 'Bearer ' prefix 
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
                RefreshToken = refreshResult.Data!.Token!,
                RefreshTokenExpiresUtc = refreshResult.Data.RefreshTokenExpiresUtc
            }
        };
    }
}
