using My_Social_Secure_Api.Models.Identity;

namespace My_Social_Secure_Api.Interfaces.Services.Auth;

public interface IJwtTokenGenerator
{
    public string GenerateToken(ApplicationUser user);
    public string GenerateTemporary2FaToken(ApplicationUser user);
}