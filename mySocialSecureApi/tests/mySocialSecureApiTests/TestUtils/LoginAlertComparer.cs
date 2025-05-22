using My_Social_Secure_Api.Models.Entities.Auth;

namespace My_Social_Secure_Api_Tests.TestUtils;

public class LoginAlertComparer : IEqualityComparer<LoginAlertModel>
{
    public bool Equals(LoginAlertModel? x, LoginAlertModel? y)
    {
        if (x is null || y is null)
            return false;

        return x.Id == y.Id &&
               x.UserId == y.UserId &&
               x.LoginTime == y.LoginTime;
    }

    public int GetHashCode(LoginAlertModel obj)
    {
        return HashCode.Combine(obj.Id, obj.UserId, obj.LoginTime);
    }
}