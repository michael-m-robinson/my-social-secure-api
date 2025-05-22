namespace My_Social_Secure_Api.Interfaces.Services.Utilities;

public interface IPwnedPasswordService
{
    Task<bool> IsPasswordPwnedAsync(string password);
}