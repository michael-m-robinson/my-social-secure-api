using My_Social_Secure_Api.Interfaces.Services.GeoLocation;
using My_Social_Secure_Api.Models.GeoLocation;

namespace My_Social_Secure_Api.Services.GeoLocation;

public class MaxMindGeolocationService(
    ILogger<MaxMindGeolocationService> logger,
    IHttpContextAccessor httpContextAccessor,
    IDatabaseReaderWrapper reader) : IIpGeolocationService
{
    private readonly ILogger<MaxMindGeolocationService> _logger = logger;
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;
    private readonly IDatabaseReaderWrapper _reader = reader;
    private string CorrelationId => _httpContextAccessor.HttpContext?.Items["X-Correlation-ID"]?.ToString() ?? "none";

    public async Task<string> GetLocationAsync(string ipAddress)
    {
        return await Task.Run(() =>
        {
            try
            {
                var response = GetCityResponse(ipAddress);
                var location = new LocationResultDto
                {
                    City = response.GetCityName() ?? "Unknown City",
                    Country = response.GetCountryName() ?? "Unknown Country"
                };
                
                var locationString = FormatLocation(location);
                _logger.LogInformation("Resolved location: {Location} for IP: {IP} Correlation ID: {CorrelationId}", locationString, ipAddress, CorrelationId);
                return locationString;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error resolving location for IP: {IP} Correlation ID: {CorrelationId}", ipAddress, CorrelationId);
                return "Unknown";
            }
        });
    }

    private ICityResponseWrapper GetCityResponse(string ipAddress)
    {
        return _reader.City(ipAddress);
    }

    private string FormatLocation(LocationResultDto cityResponse)
    {
        var city = cityResponse.City;
        var country = cityResponse.Country;
        return $"{city}, {country}";
    }
}