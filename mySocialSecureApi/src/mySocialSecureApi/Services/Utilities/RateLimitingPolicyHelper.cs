using System.Threading.RateLimiting;

namespace My_Social_Secure_Api.Services.Utilities;

public static class RateLimitingPolicyHelper
{
    public static Func<HttpContext, RateLimitPartition<string>> FixedPolicy(
        int permitLimit,
        double minutes,
        int queueLimit = 0)
    {
        return context =>
        {
            var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            return RateLimitPartition.GetFixedWindowLimiter(ip, _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = permitLimit,
                Window = TimeSpan.FromMinutes(minutes),
                QueueLimit = queueLimit,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst
            });
        };
    }
}

