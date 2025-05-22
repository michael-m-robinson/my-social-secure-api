using MaxMind.GeoIP2.Responses;

namespace My_Social_Secure_Api.Interfaces.Services.GeoLocation;

public interface IDatabaseReaderWrapper
{
    ICityResponseWrapper City(string ip);
}