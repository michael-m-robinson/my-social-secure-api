using System.Net.Mail;
using My_Social_Secure_Api.Interfaces.Services.Notifications;
using My_Social_Secure_Api.Models.Identity;
using My_Social_Secure_Api.Models.Notifications;

namespace My_Social_Secure_Api.Services.Notifications;

public class AdminEmailService : IAdminEmailService
{
    private readonly IEmailTemplateService _templateService;
    private readonly IEmailSender _emailSender;
    private readonly ILogger<AdminEmailService> _logger;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public AdminEmailService(
        IEmailTemplateService templateService,
        IEmailSender emailSender,
        ILogger<AdminEmailService> logger,
        IHttpContextAccessor httpContextAccessor)
    {
        _templateService = templateService;
        _emailSender = emailSender;
        _logger = logger;
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task<bool> SendRateLimitAlertAsync(ApplicationUser user, SendRateLimitAlertMetaData metaData)
    {
        var correlationId = _httpContextAccessor?.HttpContext?.Items["X-Correlation-ID"]?.ToString();
        _logger.LogInformation("SendRateLimitAlertAsync started. CorrelationId: {CorrelationId}", correlationId);

        try
        {
            ValidateUser(user);

            var replacements = BuildReplacements(user, metaData);
            var html = await LoadEmailTemplateAsync(replacements);

            await SendEmailAsync(html);
            LogEmailSent(user);

            return true;
        }
        catch (ArgumentNullException ex)
        {
            _logger.LogError(ex, "Missing required input while sending rate limit alert. UserId: {UserId}", user?.Id);
        }
        catch (KeyNotFoundException ex)
        {
            _logger.LogError(ex, "Email template not found for rate limit alert. UserId: {UserId}", user?.Id);
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogError(ex, "Invalid operation during rate limit alert. UserId: {UserId}", user?.Id);
        }
        catch (SmtpException ex)
        {
            _logger.LogError(ex, "SMTP error sending rate limit alert. UserId: {UserId}", user?.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error sending rate limit alert. UserId: {UserId}", user?.Id);
        }

        return false;
    }

    private void ValidateUser(ApplicationUser user)
    {
        if (user == null)
        {
            _logger.LogError("User is null when trying to send rate limit alert.");
            throw new ArgumentNullException(nameof(user));
        }
    }

    private Dictionary<string, string> BuildReplacements(ApplicationUser user, SendRateLimitAlertMetaData metaData)
    {
        return new Dictionary<string, string>
        {
            { "UserId", user.Id },
            { "UserName", user.UserName ?? "Unknown" },
            { "Email", user.Email ?? "Unknown" },
            { "IPAddress", metaData.IpAddress },
            { "Endpoint", metaData.Endpoint },
            { "TimeUtc", DateTime.UtcNow.ToString("MMM dd, yyyy h:mmtt") }
        };
    }

    private async Task<string> LoadEmailTemplateAsync(Dictionary<string, string> replacements)
    {
        return await _templateService.LoadTemplateAsync("RateLimitAlertTemplate", replacements);
    }

    private async Task SendEmailAsync(string html)
    {
        await _emailSender.SendEmailAsync("mike.maurice.robinson@gmail.com", "Rate Limit Breach Alert", html);
    }

    private void LogEmailSent(ApplicationUser user)
    {
        _logger.LogInformation("Rate limit breach alert sent to {Email} for user {UserId} at {TimeUtc}",
            user.Email, user.Id, DateTime.UtcNow.ToString("MMM dd, yyyy h:mmtt"));
    }
}
