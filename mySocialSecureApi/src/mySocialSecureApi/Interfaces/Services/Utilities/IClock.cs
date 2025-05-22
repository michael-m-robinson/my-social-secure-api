namespace My_Social_Secure_Api.Interfaces.Services.Utilities;

public interface IClock
{
    DateTime UtcNow { get; }
    DateTime Now { get; }
}