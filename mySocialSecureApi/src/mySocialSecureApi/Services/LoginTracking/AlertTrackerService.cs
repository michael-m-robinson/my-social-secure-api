using System.Collections.Concurrent;
using My_Social_Secure_Api.Interfaces.Services.LoginTracking;
using My_Social_Secure_Api.Interfaces.Services.Utilities;
using My_Social_Secure_Api.Models.Security;

namespace My_Social_Secure_Api.Services.LoginTracking;

public class AlertTrackerService(
    IClock clock,
    ILogger<AlertTrackerService> logger,
    IHttpContextAccessor httpContextAccessor)
    : IAlertTrackerService
{
    private readonly IClock _clock = clock ?? throw new ArgumentNullException(nameof(clock));
    private readonly ILogger _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
    private readonly ConcurrentDictionary<string, EmailAlertInfo> _tracker = new();

    public bool ShouldSend(string userId, string breachType)
    {
        var correlationId = _httpContextAccessor.HttpContext?.Items["X-Correlation-ID"]?.ToString();
        _logger.LogInformation("ShouldSend method entered. CorrelationId: {CorrelationId}", correlationId);

        try
        {
            var key = GenerateKey(userId, breachType);
            var now = _clock.UtcNow;
            var info = _tracker.GetOrAdd(key, _ => new EmailAlertInfo());

            lock (info)
            {
                ResetIfNecessary(info, now);

                if (CanSendAlert(info, now))
                {
                    IncrementAlertCount(info, now);
                    return true;
                }
            }

            return false;
        }
        catch (ArgumentNullException ex)
        {
            _logger.LogError(ex, "Null argument in ShouldSend for userId: {UserId}, breachType: {BreachType}", userId, breachType);
            return false;
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogError(ex, "Invalid operation in ShouldSend for userId: {UserId}, breachType: {BreachType}", userId, breachType);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed in ShouldSend for userId: {UserId}, breachType: {BreachType}", userId, breachType);
            return false;
        }
    }

    private string GenerateKey(string userId, string breachType) => $"{userId}|{breachType}";

    private void ResetIfNecessary(EmailAlertInfo info, DateTime now)
    {
        if (now - info.LastResetUtc > TimeSpan.FromDays(1))
        {
            info.Count = 0;
            info.LastResetUtc = now;
        }
    }

    private bool CanSendAlert(EmailAlertInfo info, DateTime now)
    {
        var timeSinceLast = now - info.LastSentUtc;
        return info.Count < 3 && timeSinceLast >= TimeSpan.FromMinutes(10);
    }

    private void IncrementAlertCount(EmailAlertInfo info, DateTime now)
    {
        info.Count++;
        info.LastSentUtc = now;
    }
}