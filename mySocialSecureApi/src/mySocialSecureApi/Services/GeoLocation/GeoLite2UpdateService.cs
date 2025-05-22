using My_Social_Secure_Api.Interfaces.Services.GeoLocation;

namespace My_Social_Secure_Api.Services.GeoLocation;

public class GeoLite2UpdateService(
    ILogger<GeoLite2UpdateService> logger,
    IHttpContextAccessor httpContextAccessor,
    IWebHostEnvironment env,
    IGeoLite2Downloader downloader)
    : BackgroundService
{
    private readonly ILogger<GeoLite2UpdateService> _logger = logger;
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;
    private readonly IGeoLite2Downloader _downloader = downloader;
    private readonly string _licenseKey = GetLicenseKey();
    private readonly TimeSpan _updateInterval = TimeSpan.FromDays(30);
    private readonly string _appDataPath = GetAppDataPath(env);

    private string CorrelationId => _httpContextAccessor.HttpContext?.Items["X-Correlation-ID"]?.ToString() ?? "none";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await UpdateDatabaseAsync(stoppingToken);
            await Task.Delay(_updateInterval, stoppingToken);
        }
    }

    private static string GetLicenseKey()
    {
        return Environment.GetEnvironmentVariable("MAXMIND_LICENSE_KEY") ??
               throw new InvalidOperationException("License key not set.");
    }

    private static string GetAppDataPath(IWebHostEnvironment env)
    {
        return Path.Combine(env.ContentRootPath, "App_Data");
    }

    private async Task UpdateDatabaseAsync(CancellationToken stoppingToken)
    {
        try
        {
            _logger.LogInformation("Updating GeoLite2 database... Correlation ID: {CorrelationId}", CorrelationId);
            var outputPath = Path.Combine(_appDataPath, "GeoLite2-City.mmdb");
            await _downloader.DownloadAndExtractAsync(_licenseKey, outputPath);
            _logger.LogInformation("GeoLite2 database update completed. Correlation ID: {CorrelationId}", CorrelationId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to update GeoLite2 database. Correlation ID: {CorrelationId}", CorrelationId);
        }
    }
}
