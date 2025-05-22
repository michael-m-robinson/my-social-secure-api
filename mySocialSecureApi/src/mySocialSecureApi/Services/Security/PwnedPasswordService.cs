using System.Security.Cryptography;
using System.Text;
using My_Social_Secure_Api.Interfaces.Services.Utilities;

namespace My_Social_Secure_Api.Services.Security;

public class PwnedPasswordService(
    HttpClient httpClient,
    ILogger<PwnedPasswordService> logger,
    IHttpContextAccessor httpContextAccessor) : IPwnedPasswordService
{
    private readonly HttpClient _httpClient = httpClient;
    private readonly ILogger<PwnedPasswordService> _logger = logger;
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;

    private string CorrelationId =>
        _httpContextAccessor.HttpContext?.Items["X-Correlation-ID"]?.ToString() ?? "none";

    public async Task<bool> IsPasswordPwnedAsync(string password)
    {
        _logger.LogInformation("Entered IsPasswordPwnedAsync. CorrelationId: {CorrelationId}", CorrelationId);

        try
        {
            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Password must not be null or whitespace.", nameof(password));

            using var sha1 = SHA1.Create();
            var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(password));
            var hashString = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();

            if (hashString.Length < 6)
                throw new InvalidOperationException("Computed SHA1 hash is unexpectedly short.");

            var prefix = hashString[..5];
            var suffix = hashString[5..];

            HttpResponseMessage response;
            try
            {
                response = await _httpClient.GetAsync($"https://api.pwnedpasswords.com/range/{prefix}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "HTTP request to Pwned Passwords API failed. CorrelationId: {CorrelationId}", CorrelationId);
                throw new HttpRequestException("Unable to contact Pwned Passwords API.");
            }

            if (!response.IsSuccessStatusCode)
            {
                var errorBody = await response.Content.ReadAsStringAsync();
                _logger.LogError("API responded with status code {StatusCode}. Body: {Body}. CorrelationId: {CorrelationId}",
                    response.StatusCode, errorBody, CorrelationId);
                throw new HttpRequestException("Pwned Passwords API returned an error.");
            }

            var content = await response.Content.ReadAsStringAsync();

            foreach (var line in content.Split('\n'))
            {
                var parts = line.Split(':');
                if (parts.Length < 2) continue;

                if (parts[0].Trim().Equals(suffix, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }
        catch (ArgumentException ex)
        {
            _logger.LogError(ex, "Invalid password argument. CorrelationId: {CorrelationId}", CorrelationId);
            throw;
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "HTTP communication with Pwned Passwords API failed. CorrelationId: {CorrelationId}", CorrelationId);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error while checking pwned password. CorrelationId: {CorrelationId}", CorrelationId);
            throw new HttpRequestException("An error occurred while checking password against Pwned Passwords API.");
        }
    }
}