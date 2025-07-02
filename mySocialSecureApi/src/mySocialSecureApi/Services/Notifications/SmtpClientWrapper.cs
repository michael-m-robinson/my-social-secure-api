using System.Net;
using System.Net.Mail;
using My_Social_Secure_Api.Interfaces.Services.Notifications;

namespace My_Social_Secure_Api.Services.Notifications;

public class SmtpClientWrapper : ISmtpClient
{
    private readonly SmtpClient _client;
    private readonly ILogger<SmtpClientWrapper> _logger;

    public SmtpClientWrapper(string host, int port, string username, string password, ILogger<SmtpClientWrapper> logger)
    {
        _logger = logger;
        _client = new SmtpClient(host, port)
        {
            Credentials = new NetworkCredential(username, password),
            EnableSsl = true
        };
    }

    public async Task SendMailAsync(MailMessage message, IHttpContextAccessor httpContextAccessor, ILogger logger)
    {
        var correlationId = httpContextAccessor?.HttpContext?.Items["X-Correlation-ID"]?.ToString();
        logger.LogInformation("SendMailAsync started. CorrelationId: {CorrelationId}", correlationId);

        try
        {
            ValidateMessage(message);
            logger.LogInformation("Sending email to {Recipient}", message.To[0].Address);
            await _client.SendMailAsync(message);
        }
        catch (ArgumentNullException ex)
        {
            logger.LogError(ex, "Mail message was null.");
            throw;
        }
        catch (InvalidOperationException ex)
        {
            logger.LogError(ex, "Mail message is invalid or SMTP client is not configured correctly.");
            throw;
        }
        catch (SmtpFailedRecipientException ex)
        {
            logger.LogError(ex, "Failed to deliver email to recipient: {FailedRecipient}", ex.FailedRecipient);
            throw;
        }
        catch (SmtpException ex)
        {
            logger.LogError(ex, "SMTP error occurred while sending email.");
            throw;
        }
        catch (TimeoutException ex)
        {
            logger.LogError(ex, "SMTP timeout occurred while sending email.");
            throw;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Unexpected error while sending email.");
            throw;
        }
    }

    private void ValidateMessage(MailMessage message)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message), "MailMessage cannot be null.");
        }

        if (message.To.Count == 0)
        {
            throw new InvalidOperationException("MailMessage must have at least one recipient.");
        }
    }

    public Task SendMailAsync(MailMessage message)
    {
        // Fallback log without correlation
        _logger.LogInformation("SendMailAsync called without context. To: {Recipient}", message.To.FirstOrDefault()?.Address);

        try
        {
            ValidateMessage(message);
            return _client.SendMailAsync(message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while sending mail without context.");
            throw;
        }
    }

}
