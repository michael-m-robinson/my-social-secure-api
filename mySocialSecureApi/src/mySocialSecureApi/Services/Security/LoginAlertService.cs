using System.Net.Mail;
using Microsoft.EntityFrameworkCore;
using My_Social_Secure_Api.Data;
using My_Social_Secure_Api.Interfaces.Services.DeviceRecognition;
using My_Social_Secure_Api.Interfaces.Services.GeoLocation;
using My_Social_Secure_Api.Interfaces.Services.Notifications;
using My_Social_Secure_Api.Interfaces.Services.Security;
using My_Social_Secure_Api.Models.Dtos.Notifications;
using My_Social_Secure_Api.Models.Entities.Auth;
using My_Social_Secure_Api.Models.Identity;

namespace My_Social_Secure_Api.Services.Security;

public class LoginAlertService(
    ApplicationDbContext context,
    IHttpContextAccessor httpContextAccessor,
    IUserEmailService userEmailService,
    IIpGeolocationService geoService,
    IDeviceRecognitionService deviceRecognition,
    ILogger<LoginAlertService> logger) : ILoginAlertService
{
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;
    private readonly ILogger<LoginAlertService> _logger = logger;

    private string CorrelationId =>
        _httpContextAccessor?.HttpContext?.Items["X-Correlation-ID"]?.ToString() ?? "none";

    public async Task HandleLoginAlertAsync(ApplicationUser user, string domain)
    {
        try
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext == null) return;

            var ip = GetIpAddress(httpContext);
            var userAgent = GetUserAgent(httpContext);
            var deviceSummary = GetDeviceSummary(userAgent);
            var location = await GetLocationFromIp(ip);

            if (await IsExistingLoginAlert(user.Id, ip))
            {
                _logger.LogWarning(
                    "Login alert already exists for user {UserId} with IP {Ip}. CorrelationId: {CorrelationId}",
                    user.Id, ip, CorrelationId);
                return;
            }

            var isKnown = await deviceRecognition.IsKnownDeviceAsync(user, ip, userAgent);
            var publicAlert = BuildPublicAlert(ip, location, deviceSummary, isKnown);
            var privateAlert = BuildPrivateAlert(user, ip, location, userAgent, domain);

            if (!isKnown)
            {
                _logger.LogInformation(
                    "Unknown device detected for user {UserName} with IP {Ip}. CorrelationId: {CorrelationId}",
                    user.UserName, ip, CorrelationId);
                await HandleUnknownDevice(user, ip, userAgent, location, publicAlert, privateAlert);
            }
            else
            {
                _logger.LogInformation(
                    "Known device detected for user {UserName} with IP {Ip}. CorrelationId: {CorrelationId}",
                    user.UserName, ip, CorrelationId);
                await HandleKnownDevice(user, publicAlert, privateAlert);
            }
        }
        catch (DbUpdateException ex)
        {
            _logger.LogError(ex,
                "Database update failed while handling login alert for user {UserId}. CorrelationId: {CorrelationId}",
                user?.Id, CorrelationId);
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "Geo IP location service failed for IP {Ip}. CorrelationId: {CorrelationId}",
                _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString(), CorrelationId);
        }
        catch (SmtpException ex)
        {
            _logger.LogError(ex,
                "SMTP failure while sending login alert email for user {UserId}. CorrelationId: {CorrelationId}",
                user?.Id, CorrelationId);
        }
        catch (ArgumentException ex)
        {
            _logger.LogError(ex,
                "Invalid argument in login alert flow for user {UserId}. CorrelationId: {CorrelationId}", user?.Id,
                CorrelationId);
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogError(ex,
                "Invalid operation while handling login alert for user {UserId}. CorrelationId: {CorrelationId}",
                user?.Id, CorrelationId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Unexpected error occurred while handling login alert for user {UserId}. CorrelationId: {CorrelationId}",
                user?.Id, CorrelationId);
        }
    }

    private string GetIpAddress(HttpContext context) =>
        context.Connection.RemoteIpAddress?.ToString() ?? "Unknown";

    private string GetUserAgent(HttpContext context) =>
        context.Request.Headers["User-Agent"].ToString();

    private string GetDeviceSummary(string userAgent) =>
        string.IsNullOrWhiteSpace(userAgent) ? "Unknown device" : deviceRecognition.GetDeviceSummary(userAgent);

    private async Task<bool> IsExistingLoginAlert(string userId, string ip) =>
        await context.LoginAlerts.AnyAsync(a => a.UserId == userId && a.IpAddress == ip);

    private LoginAlertDto BuildPublicAlert(string ip, string location, string deviceSummary, bool isKnown) => new()
    {
        IpAddress = ip,
        Location = location,
        LoginTime = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"),
        DeviceSummary = deviceSummary,
        IsKnown = isKnown
    };

    private LoginAlertModel BuildPrivateAlert(ApplicationUser user, string ip, string location, string userAgent,
        string domain) => new()
    {
        UserId = user.Id,
        IpAddress = ip,
        Location = location,
        LoginTime = DateTime.UtcNow,
        UserAgent = string.IsNullOrWhiteSpace(userAgent) ? "Unknown device" : userAgent,
        Domain = domain
    };

    private async Task HandleUnknownDevice(ApplicationUser user, string ip, string userAgent, string location,
        LoginAlertDto publicAlert, LoginAlertModel privateAlert)
    {
        await deviceRecognition.RegisterDeviceAsync(user, ip, userAgent, location);
        _logger.LogInformation("New device registered for user {UserName} with IP {Ip}. CorrelationId: {CorrelationId}",
            user.UserName, ip, CorrelationId);

        await userEmailService.SendLoginAlertAsync(user, publicAlert);
        _logger.LogInformation(
            "Login alert email sent to user {UserName} for new device. CorrelationId: {CorrelationId}", user.UserName,
            CorrelationId);

        await SaveLoginAlert(privateAlert);
    }

    private async Task HandleKnownDevice(ApplicationUser user, LoginAlertDto publicAlert, LoginAlertModel privateAlert)
    {
        await userEmailService.SendLoginAlertAsync(user, publicAlert);
        _logger.LogInformation(
            "Login alert email sent to user {UserName} for known device. CorrelationId: {CorrelationId}", user.UserName,
            CorrelationId);

        await SaveLoginAlert(privateAlert);
    }

    private async Task SaveLoginAlert(LoginAlertModel privateAlert)
    {
        context.LoginAlerts.Add(privateAlert);
        await context.SaveChangesAsync();
        _logger.LogInformation("New login alert created for user {UserId} with IP {Ip}. CorrelationId: {CorrelationId}",
            privateAlert.UserId, privateAlert.IpAddress, CorrelationId);
    }

    private async Task<string> GetLocationFromIp(string ip) =>
        await geoService.GetLocationAsync(ip);
}