namespace My_Social_Secure_Api.Interfaces.Services.Auth;

public interface ITokenParserService
{
    (string UserId, string UserName) ExtractUserInfo(string? bearerToken);
}