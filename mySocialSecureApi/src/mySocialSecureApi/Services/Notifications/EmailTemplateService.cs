using System.IO;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using My_Social_Secure_Api.Interfaces.Services.Notifications;
// ReSharper disable ConvertToPrimaryConstructor

namespace My_Social_Secure_Api.Services.Notifications;

public class EmailTemplateService : IEmailTemplateService
{
    private readonly IWebHostEnvironment _env;
    private readonly ILogger<EmailTemplateService> _logger;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public EmailTemplateService(IWebHostEnvironment env, ILogger<EmailTemplateService> logger, IHttpContextAccessor httpContextAccessor)
    {
        _env = env;
        _logger = logger;
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task<string> LoadTemplateAsync(string templateName, Dictionary<string, string> replacements, IHttpContextAccessor httpContextAccessor, ILogger logger)
    {
        var correlationId = httpContextAccessor?.HttpContext?.Items["X-Correlation-ID"]?.ToString();
        logger.LogInformation("LoadTemplateAsync started. CorrelationId: {CorrelationId}", correlationId);

        try
        {
            ValidateReplacements(replacements);

            var path = GetTemplatePath(templateName);
            var content = await ReadTemplateContentAsync(path);

            logger.LogInformation("Loading email template: {TemplateName}", templateName);
            return ApplyReplacements(content, replacements);
        }
        catch (ArgumentNullException ex)
        {
            logger.LogError(ex, "Template name or replacements are null.");
            throw;
        }
        catch (FileNotFoundException ex)
        {
            logger.LogError(ex, "Template file not found: {FileName}", ex.FileName);
            throw;
        }
        catch (UnauthorizedAccessException ex)
        {
            logger.LogError(ex, "Unauthorized access while loading template.");
            throw;
        }
        catch (IOException ex)
        {
            logger.LogError(ex, "I/O error while reading template file.");
            throw;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Unexpected error while loading email template.");
            throw;
        }
    }

    private void ValidateReplacements(Dictionary<string, string> replacements)
    {
        if (replacements == null)
            throw new ArgumentNullException(nameof(replacements));
    }

    private string GetTemplatePath(string templateName)
    {
        var path = Path.Combine(_env.ContentRootPath, "EmailTemplates", $"{templateName}.html");

        if (!File.Exists(path))
            throw new FileNotFoundException("Email template not found", path);

        return path;
    }

    private async Task<string> ReadTemplateContentAsync(string path)
    {
        return await File.ReadAllTextAsync(path);
    }

    private string ApplyReplacements(string content, Dictionary<string, string> replacements)
    {
        foreach (var pair in replacements)
        {
            content = content.Replace($"{{{{{pair.Key}}}}}", pair.Value);
        }

        return content;
    }
    
    public async Task<string> LoadTemplateAsync(string templateName, Dictionary<string, string> replacements)
    {
        var correlationId = _httpContextAccessor?.HttpContext?.Items["X-Correlation-ID"]?.ToString();
        _logger.LogInformation("LoadTemplateAsync started. CorrelationId: {CorrelationId}", correlationId);

        try
        {
            ValidateReplacements(replacements);
            var path = GetTemplatePath(templateName);
            var content = await ReadTemplateContentAsync(path);

            return ApplyReplacements(content, replacements);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error loading template {TemplateName}.", templateName);
            throw;
        }
    }


}
