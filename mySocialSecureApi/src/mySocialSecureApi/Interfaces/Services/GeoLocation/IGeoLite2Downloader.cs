namespace My_Social_Secure_Api.Interfaces.Services.GeoLocation;

public interface IGeoLite2Downloader
{
    Task DownloadAndExtractAsync(string licenseKey, string outputPath);
}