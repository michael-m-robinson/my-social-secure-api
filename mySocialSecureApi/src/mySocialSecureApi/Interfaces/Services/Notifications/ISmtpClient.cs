using System.Net.Mail;

namespace My_Social_Secure_Api.Interfaces.Services.Notifications;

public interface ISmtpClient
{
    Task SendMailAsync(MailMessage message);
}