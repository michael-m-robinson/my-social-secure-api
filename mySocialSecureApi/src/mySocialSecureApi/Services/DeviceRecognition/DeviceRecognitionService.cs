using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using My_Social_Secure_Api.Data;
using My_Social_Secure_Api.Interfaces.Services.DeviceRecognition;
using My_Social_Secure_Api.Models.Entities.DeviceRecognition;
using My_Social_Secure_Api.Models.Identity;

namespace My_Social_Secure_Api.Services.DeviceRecognition;

public class DeviceRecognitionService : IDeviceRecognitionService
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<DeviceRecognitionService> _logger;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public DeviceRecognitionService(
        ApplicationDbContext context,
        ILogger<DeviceRecognitionService> logger,
        IHttpContextAccessor httpContextAccessor)
    {
        _context = context;
        _logger = logger;
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task<bool> IsKnownDeviceAsync(ApplicationUser user, string ip, string userAgent)
    {
        LogCorrelation("IsKnownDeviceAsync");

        try
        {
            var fingerprint = GenerateFingerprint(ip, userAgent);
            return await _context.DeviceRecognitions
                .AnyAsync(d => d.UserId == user.Id && d.DeviceFingerprint == fingerprint);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking device recognition for user {UserId}.", user.Id);
            return false; // Fail safe: treat as unknown device
        }
    }


    public async Task RegisterDeviceAsync(ApplicationUser user, string ip, string userAgent, string? location)
    {
        LogCorrelation("RegisterDeviceAsync");

        try
        {
            var fingerprint = GenerateFingerprint(ip, userAgent);
            var existingDevice = await GetExistingDeviceAsync(user.Id, fingerprint);

            if (existingDevice != null)
            {
                UpdateLastSeen(existingDevice);
                _context.Entry(existingDevice).Property(d => d.LastSeen).IsModified = true;
            }
            else
            {
                await AddNewDeviceAsync(user.Id, fingerprint, userAgent, location);
            }

            await _context.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred while registering the device for user {UserId}.", user.Id);
            throw;
        }
    }

    public string GetDeviceSummary(string? userAgent)
    {
        LogCorrelation("GetDeviceSummary");

        try
        {
            if (string.IsNullOrEmpty(userAgent))
                return "Unknown Device";

            var os = DetectOperatingSystem(userAgent);
            var browser = DetectBrowser(userAgent);

            return $"{browser} on {os}";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error parsing user agent string.");
            return "Unknown Device";
        }
    }



    private async Task<DeviceRecognitionModel?> GetExistingDeviceAsync(string userId, string fingerprint)
    {
        return await _context.DeviceRecognitions
            .FirstOrDefaultAsync(d => d.UserId == userId && d.DeviceFingerprint == fingerprint);
    }

    private void UpdateLastSeen(DeviceRecognitionModel device)
    {
        device.LastSeen = DateTime.UtcNow;
    }

    private async Task AddNewDeviceAsync(string userId, string fingerprint, string userAgent, string? location)
    {
        var newDevice = new DeviceRecognitionModel
        {
            UserId = userId,
            DeviceFingerprint = fingerprint,
            DeviceName = userAgent,
            Location = location
        };
        await _context.DeviceRecognitions.AddAsync(newDevice);
    }

    private string DetectOperatingSystem(string userAgent)
    {
        userAgent = userAgent.ToLowerInvariant();

        if (userAgent.Contains("iphone")) return "iPhone";
        if (userAgent.Contains("ipad")) return "iPad";
        if (userAgent.Contains("android")) return "Android Device";
        if (userAgent.Contains("windows nt")) return "Windows PC";
        if (userAgent.Contains("mac os x")) return "Mac";
        if (userAgent.Contains("linux")) return "Linux";

        return "Unknown OS";
    }

    private string DetectBrowser(string userAgent)
    {
        userAgent = userAgent.ToLowerInvariant();

        if (userAgent.Contains("edg/")) return "Edge";
        if (userAgent.Contains("chrome/") && !userAgent.Contains("edg/") && !userAgent.Contains("opr/")) return "Chrome";
        if (userAgent.Contains("safari/") && !userAgent.Contains("chrome/") && !userAgent.Contains("crios/")) return "Safari";
        if (userAgent.Contains("firefox/")) return "Firefox";
        if (userAgent.Contains("msie") || userAgent.Contains("trident/")) return "Internet Explorer";

        return "Unknown Browser";
    }

    private string GenerateFingerprint(string ip, string userAgent)
    {
        using var sha256 = SHA256.Create();
        var input = $"{ip}-{userAgent}";
        var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
        return Convert.ToBase64String(hash);
    }

    private void LogCorrelation(string methodName)
    {
        var correlationId = _httpContextAccessor?.HttpContext?.Items["X-Correlation-ID"]?.ToString();
        _logger.LogInformation("{Method} started. CorrelationId: {CorrelationId}", methodName, correlationId);
    }
}
