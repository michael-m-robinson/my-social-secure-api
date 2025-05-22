using My_Social_Secure_Api.Interfaces.Services.RateLimiting;

namespace My_Social_Secure_Api.Services.RateLimiting;

public class RateLimitResponseWriter : IRateLimitResponseWriter
{
    public async Task WriteAsync(HttpContext httpContext, string message, CancellationToken token)
    {
        try
        {
            SetResponseHeaders(httpContext);

            var response = CreateResponse(message);

            var logger = httpContext.RequestServices.GetService<ILogger<RateLimitResponseWriter>>();
            logger?.LogInformation("Writing rate limit response: {Message}", message);

            await WriteResponseAsync(httpContext, response, token);
        }
        catch (InvalidOperationException ex)
        {
            var logger = httpContext.RequestServices.GetService<ILogger<RateLimitResponseWriter>>();
            logger?.LogWarning(ex, "Failed to write rate limit response. The response has likely already started.");
        }
        catch (OperationCanceledException)
        {
            // Expected; do nothing
        }
        catch (IOException ex)
        {
            var logger = httpContext.RequestServices.GetService<ILogger<RateLimitResponseWriter>>();
            logger?.LogWarning(ex, "I/O error while writing rate limit response. Client may have disconnected.");
        }
        catch (Exception ex)
        {
            var logger = httpContext.RequestServices.GetService<ILogger<RateLimitResponseWriter>>();
            logger?.LogError(ex, "Unexpected error while writing rate limit response.");
        }
    }

    private void SetResponseHeaders(HttpContext httpContext)
    {
        httpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        httpContext.Response.ContentType = "application/json";
    }

    private object CreateResponse(string message)
    {
        return new
        {
            message,
            timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        };
    }

    private async Task WriteResponseAsync(HttpContext httpContext, object response, CancellationToken token)
    {
        await httpContext.Response.WriteAsJsonAsync(response, token);
    }
}
