using My_Social_Secure_Api.Interfaces.Services.Notifications;
using My_Social_Secure_Api.Models.Dtos.Notifications;
using My_Social_Secure_Api.Models.Identity;
using My_Social_Secure_Api.Models.Notifications;

// ReSharper disable ConvertToPrimaryConstructor

namespace My_Social_Secure_Api.Services.Notifications;

public class UserEmailService : IUserEmailService
{
    private readonly IEmailSender _emailSender;
    private readonly IEmailTemplateService _templateService;
    private readonly ILogger<UserEmailService> _logger;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private const string EmailNullWarning = "User email is null.";
    private const string EmailConfirmationSubject = "Confirm Your Email";
    private const string PasswordChangeConfirmationSubject = "Password Change Confirmation";
    private const string TwoFactorCodeSubject = "Your 2FA Code";
    private const string EmailChangeConfirmationSubject = "Email Change Confirmation";
    private const string LoginAlertSubject = "New Login Alert";

    public UserEmailService(
        IEmailSender emailSender,
        IEmailTemplateService templateService,
        ILogger<UserEmailService> logger,
        IHttpContextAccessor httpContextAccessor)
    {
        _emailSender = emailSender;
        _templateService = templateService;
        _logger = logger;
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task SendTwoFactorCodeEmailAsync(ApplicationUser user, LoginMetadata metadata)
    {
        LogWithCorrelation("SendTwoFactorCodeEmailAsync");
        try
        {
            var html = await GenerateEmailContentAsync("TwoFactorCodeTemplate",
                BuildTwoFactorReplacements(user, metadata));
            await SendEmailAsync(user.Email, TwoFactorCodeSubject, html);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send 2FA email to {UserId}", user.Id);
        }
    }

    public async Task SendEmailConfirmationAsync(ApplicationUser user, LoginMetadata metadata)
    {
        LogWithCorrelation("SendEmailConfirmationAsync");
        try
        {
            var html = await GenerateEmailContentAsync("EmailConfirmationTemplate",
                BuildEmailConfirmationReplacements(user, metadata));
            await SendEmailAsync(user.Email, EmailConfirmationSubject, html);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send email confirmation to {UserId}", user.Id);
        }
    }

    public async Task SendPasswordChangeConfirmationAsync(ApplicationUser user, LoginMetadata metadata)
    {
        LogWithCorrelation("SendPasswordChangeConfirmationAsync");
        try
        {
            var html = await GenerateEmailContentAsync("PasswordChangeConfirmationTemplate",
                BuildPasswordChangeReplacements(user, metadata));
            await SendEmailAsync(user.Email, PasswordChangeConfirmationSubject, html);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send password change confirmation to {UserId}", user.Id);
        }
    }

    public async Task SendEmailChangeConfirmationAsync(ApplicationUser user, string newEmail)
    {
        LogWithCorrelation("SendEmailChangeConfirmationAsync");
        try
        {
            var html = await GenerateEmailContentAsync("EmailChangeConfirmationTemplate",
                BuildEmailChangeReplacements(user, newEmail));
            await SendEmailAsync(newEmail, EmailChangeConfirmationSubject, html); // <-- use newEmail
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send email change confirmation to {UserId}", user.Id);
        }
    }

    public async Task SendLoginAlertAsync(ApplicationUser user, LoginAlertDto loginAlert)
    {
        LogWithCorrelation("SendLoginAlertAsync");
        try
        {
            var html = await GenerateEmailContentAsync("LoginAlertTemplate",
                BuildLoginAlertReplacements(user, loginAlert));
            await SendEmailAsync(user.Email, LoginAlertSubject, html);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send login alert to {UserId}", user.Id);
        }
    }

    public async Task SendReportAlertAsync(ReportAlertDto alert)
    {
        LogWithCorrelation("SendReportAlertAsync");
        try
        {
            var html = await GenerateEmailContentAsync("ReportAlertTemplate", BuildReportAlertReplacements(alert));
            await SendEmailAsync(alert.Email, "New Report Available", html);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send report alert to {Email}", alert.Email);
        }
    }

    // === Helpers ===

    private void LogWithCorrelation(string method)
    {
        var correlationId = _httpContextAccessor.HttpContext?.Items["X-Correlation-ID"]?.ToString();
        _logger.LogInformation("{Method} started. CorrelationId: {CorrelationId}", method, correlationId);
    }

    private async Task<string> GenerateEmailContentAsync(string template, Dictionary<string, string> replacements)
    {
        var html = await _templateService.LoadTemplateAsync(template, replacements);
        if (html == null)
        {
            _logger.LogWarning("{Template} email template returned null content.", template);
            throw new InvalidOperationException("Email template content was null.");
        }

        return html;
    }

    private async Task SendEmailAsync(string? email, string subject, string html)
    {
        if (string.IsNullOrEmpty(email))
        {
            _logger.LogWarning(EmailNullWarning);
            throw new ArgumentNullException(nameof(email), EmailNullWarning);
        }

        await _emailSender.SendEmailAsync(email, subject, html);
    }

    private static Dictionary<string, string> BuildTwoFactorReplacements(ApplicationUser user, LoginMetadata meta) =>
        new()
        {
            { "UserName", user.UserName ?? "User" },
            { "SignInLink", meta.RequestLink! },
            { "Domain", meta.Domain! }
        };

    private static Dictionary<string, string> BuildEmailConfirmationReplacements(ApplicationUser user,
        LoginMetadata meta) => new()
    {
        { "UserName", user.UserName ?? "User" },
        { "ConfirmLink", meta.RequestLink! }
    };

    private static Dictionary<string, string>
        BuildPasswordChangeReplacements(ApplicationUser user, LoginMetadata meta) => new()
    {
        { "UserName", user.UserName ?? "User" },
        { "ConfirmLink", meta.RequestLink! }
    };

    private static Dictionary<string, string> BuildEmailChangeReplacements(ApplicationUser user, string callbackUrl) =>
        new()
        {
            { "UserName", user.UserName ?? "User" },
            { "ConfirmLink", callbackUrl }
        };

    private static Dictionary<string, string> BuildLoginAlertReplacements(ApplicationUser user, LoginAlertDto alert)
    {
        var replacements = new Dictionary<string, string>
        {
            { "UserName", user.UserName! },
            { "IpAddress", alert.IpAddress },
            { "Location", alert.Location },
            { "LoginTime", alert.LoginTime },
            { "Device", alert.DeviceSummary },
            {
                "DeviceRecognitionNotice", alert.IsKnown
                    ? ""
                    : "<div class='new-device'><h3>🔒 New Device Detected</h3>" +
                      "<p>This login came from a device we haven’t seen before. " +
                      "If this wasn’t you, please reset your password " +
                      "immediately and contact support.</p></div>"
            }
        };

        return replacements;
    }

    private static Dictionary<string, string> BuildReportAlertReplacements(ReportAlertDto alert) => new()
    {
        { "AdminName", alert.AdminName },
        { "FileName", alert.FileName },
        { "GeneratedDate", alert.GeneratedDate.ToString("yyyy-MM-dd") },
        { "FilePath", alert.FilePath }
    };
}