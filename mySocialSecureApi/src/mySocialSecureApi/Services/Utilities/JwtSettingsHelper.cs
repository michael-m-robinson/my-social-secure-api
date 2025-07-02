using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace My_Social_Secure_Api.Utilities
{
    public static class JwtSettingsHelper
    {
        public static string GetIssuer() => "mySocialSecure";

        public static string GetAudience() => "mySocialSecureUsers";

        public static SymmetricSecurityKey GetSigningKey()
        {
            var key = Environment.GetEnvironmentVariable("JWT_SECRET_KEY")
                      ?? "TestSecretKey_That_Is_At_Least_128_Bits_Long!";
            return new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
        }
    }
}
