namespace My_Social_Secure_Api.Interfaces.Services.Notifications;

public interface IEmailSender
{
    Task SendEmailAsync(string email, string subject, string message);
}