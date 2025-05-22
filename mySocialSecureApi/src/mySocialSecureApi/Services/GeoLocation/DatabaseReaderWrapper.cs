using My_Social_Secure_Api.Interfaces.Services.GeoLocation;
using MaxMind.GeoIP2;

namespace My_Social_Secure_Api.Services.GeoLocation;

public class DatabaseReaderWrapper(
    ILoggerFactory loggerFactory,
    IHttpContextAccessor httpContextAccessor,
    string dbPath) : IDatabaseReaderWrapper
{
    private readonly ILoggerFactory _loggerFactory = loggerFactory;
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;
    private readonly DatabaseReader _reader = new(dbPath);

    public ICityResponseWrapper City(string ip)
    {
        var response = _reader.City(ip);
        var cityLogger = _loggerFactory.CreateLogger<CityResponseWrapper>();

        return new CityResponseWrapper(
            cityLogger,
            _httpContextAccessor,
            response
        );
    }
}