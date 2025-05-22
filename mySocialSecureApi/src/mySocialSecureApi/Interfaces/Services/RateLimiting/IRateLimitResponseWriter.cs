namespace My_Social_Secure_Api.Interfaces.Services.RateLimiting;

public interface IRateLimitResponseWriter
{
    Task WriteAsync(HttpContext httpContext, string message, CancellationToken token);
}