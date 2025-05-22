using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using My_Social_Secure_Api.Interfaces.Services.Notifications;
// ReSharper disable ConvertToPrimaryConstructor

namespace My_Social_Secure_Api.Services.Notifications;

public class EmailSender : IEmailSender
{
    private readonly IConfiguration _config;
    private readonly ILogger<EmailSender> _logger;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ISmtpClient _smtpClient;

    public EmailSender(
        IConfiguration config,
        ILogger<EmailSender> logger,
        IHttpContextAccessor httpContextAccessor,
        ISmtpClient smtpClient)
    {
        _config = config;
        _logger = logger;
        _httpContextAccessor = httpContextAccessor;
        _smtpClient = smtpClient;
    }

    public async Task SendEmailAsync(string email, string subject, string htmlMessage)
    {
        var correlationId = _httpContextAccessor?.HttpContext?.Items["X-Correlation-ID"]?.ToString();
        _logger.LogInformation("SendEmailAsync started. CorrelationId: {CorrelationId}", correlationId);

        try
        {
            ValidateEmail(email);

            var smtpSettings = GetSmtpSettings();
            var message = CreateMailMessage(email, subject, htmlMessage, smtpSettings.FromEmail);

            await SendEmailAsync(message, smtpSettings);
        }
        catch (ArgumentNullException ex)
        {
            _logger.LogError(ex, "Missing required email field.");
        }
        catch (FormatException ex)
        {
            _logger.LogError(ex, "Invalid email format for recipient or sender.");
        }
        catch (SmtpFailedRecipientException ex)
        {
            _logger.LogError(ex, "SMTP failed to deliver email to recipient: {Email}", email);
        }
        catch (SmtpException ex)
        {
            _logger.LogError(ex, "SMTP error occurred while sending email to {Email}", email);
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogError(ex, "Invalid operation while preparing or sending email.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error while sending email to {Email}", email);
        }
    }

    private void ValidateEmail(string email)
    {
        if (string.IsNullOrEmpty(email))
        {
            _logger.LogWarning("Email address is null or empty.");
            throw new ArgumentNullException(nameof(email), "Email address cannot be null or empty.");
        }
    }

    private (string Host, int Port, string Username, string Password, string FromEmail) GetSmtpSettings()
    {
        var smtpHost = _config["Email:Smtp:Host"];
        var smtpPort = int.Parse(_config["Email:Smtp:Port"]!);
        var smtpUser = _config["Email:Smtp:Username"];
        var smtpPass = Environment.GetEnvironmentVariable("EMAIL_PASSWORD");
        var fromEmail = _config["Email:Smtp:From"];

        return (smtpHost!, smtpPort, smtpUser!, smtpPass!, fromEmail!);
    }

    private MailMessage CreateMailMessage(string email, string subject, string htmlMessage, string fromEmail)
    {
        var message = new MailMessage
        {
            From = new MailAddress(fromEmail),
            Subject = subject,
            Body = htmlMessage,
            IsBodyHtml = true
        };

        message.To.Add(email);
        return message;
    }

    private async Task SendEmailAsync(MailMessage message, (string Host, int Port, string Username, string Password, string FromEmail) smtpSettings)
    {
        using var client = new SmtpClient(smtpSettings.Host, smtpSettings.Port)
        {
            Credentials = new NetworkCredential(smtpSettings.Username, smtpSettings.Password),
            EnableSsl = true
        };

        await _smtpClient.SendMailAsync(message);
    }
}
