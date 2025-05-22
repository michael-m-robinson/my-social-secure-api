using My_Social_Secure_Api.Models.GeoLocation;

namespace My_Social_Secure_Api.Interfaces.Services.GeoLocation;

public interface IIpGeolocationService
{
    Task<string> GetLocationAsync(string ipAddress);
}