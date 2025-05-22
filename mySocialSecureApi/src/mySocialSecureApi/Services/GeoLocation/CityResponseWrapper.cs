using My_Social_Secure_Api.Interfaces.Services.GeoLocation;
using MaxMind.GeoIP2.Responses;

namespace My_Social_Secure_Api.Services.GeoLocation;

public class CityResponseWrapper(
    ILogger<CityResponseWrapper> logger,
    IHttpContextAccessor httpContextAccessor,
    CityResponse response) : ICityResponseWrapper
{
    private readonly ILogger<CityResponseWrapper> _logger = logger;
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;
    private string CorrelationId => _httpContextAccessor.HttpContext?.Items["X-Correlation-ID"]?.ToString() ?? "none";

    public string? GetCityName() => response.City?.Name;

    public string? GetCountryName() => response.Country?.Name;
}