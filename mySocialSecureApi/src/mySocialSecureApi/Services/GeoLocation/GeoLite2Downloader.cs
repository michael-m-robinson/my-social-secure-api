using System.IO.Compression;
using System.Text;
using ICSharpCode.SharpZipLib.GZip;
using My_Social_Secure_Api.Interfaces.Services.GeoLocation;
using ICSharpCode.SharpZipLib.Tar;

namespace My_Social_Secure_Api.Services.GeoLocation;

public class GeoLite2Downloader(
    ILogger<GeoLite2Downloader> logger,
    IHttpContextAccessor httpContextAccessor,
    HttpClient httpClient) : IGeoLite2Downloader
{
    private readonly ILogger<GeoLite2Downloader> _logger = logger;
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;
    private string CorrelationId => _httpContextAccessor.HttpContext?.Items["X-Correlation-ID"]?.ToString() ?? "none";

    public async Task DownloadAndExtractAsync(string licenseKey, string outputPath)
    {
        var downloadUrl = BuildDownloadUrl(licenseKey);
        var tempTarGz = Path.GetTempFileName() + ".tar.gz";

        try
        {
            _logger.LogInformation("Downloading GeoLite2 database... Correlation ID: {CorrelationId}", CorrelationId);
            await DownloadFileAsync(downloadUrl, tempTarGz);

            _logger.LogInformation("Download complete. Extracting... Correlation ID: {CorrelationId}", CorrelationId);
            await ExtractMmdbFromTarGz(tempTarGz, outputPath);

            _logger.LogInformation($"Extraction complete. MMDB saved to: {outputPath}", CorrelationId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to download or extract GeoLite2 database. Correlation ID: {CorrelationId}", CorrelationId);
            throw;
        }
        finally
        {
            CleanupTemporaryFile(tempTarGz);
        }
    }

    private string BuildDownloadUrl(string licenseKey)
    {
        return $"https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key={licenseKey}&suffix=tar.gz";
    }

    private async Task DownloadFileAsync(string url, string destinationPath)
    {
        using var response = await httpClient.GetAsync(url);
        response.EnsureSuccessStatusCode();

        await using var fs = File.Create(destinationPath);
        await response.Content.CopyToAsync(fs);
    }

    private async Task ExtractMmdbFromTarGz(string tarGzPath, string outputPath)
    {
        var tempTarPath = Path.GetTempFileName();

        try
        {
            await ExtractTarFromGz(tarGzPath, tempTarPath);
            ExtractMmdbFromTar(tempTarPath, outputPath);
        }
        finally
        {
            CleanupTemporaryFile(tempTarPath);
        }
    }

    private async Task ExtractTarFromGz(string tarGzPath, string tarPath)
    {
        _logger.LogInformation("Extracting GZip to TAR at: {TarPath}. CorrelationId: {CorrelationId}", tarPath, CorrelationId);
        
        try
        {
            await using var fileStream = File.OpenRead(tarGzPath);
            await using var gzipStream = new GZipInputStream(fileStream);
            await using var tarFileStream = File.Create(tarPath);
            await gzipStream.CopyToAsync(tarFileStream);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to extract GZip to TAR. CorrelationId: {CorrelationId}", CorrelationId);
            throw;
        }

        _logger.LogInformation("TAR file extraction completed: {TarPath}. CorrelationId: {CorrelationId}", tarPath, CorrelationId);
    }

    private void ExtractMmdbFromTar(string tarPath, string outputPath)
    {
        using var tarStream = File.OpenRead(tarPath);
        using var tarInput = new TarInputStream(tarStream, Encoding.UTF8);

        while (tarInput.GetNextEntry() is { } entry)
        {
            if (!entry.IsDirectory && entry.Name.EndsWith(".mmdb", StringComparison.OrdinalIgnoreCase))
            {
                Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
                using var outputFile = File.Create(outputPath);
                tarInput.CopyEntryContents(outputFile);
                break;
            }
        }
    }

    private void CleanupTemporaryFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
                _logger.LogInformation("Temporary file deleted: {TempPath}. CorrelationId: {CorrelationId}", path, CorrelationId);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to delete temporary file: {TempPath}. CorrelationId: {CorrelationId}", path, CorrelationId);
        }
    }

}
