using Microsoft.EntityFrameworkCore;
using My_Social_Secure_Api.Data;
using My_Social_Secure_Api.Interfaces.Services.LoginTracking;
using My_Social_Secure_Api.Models.Entities;
using My_Social_Secure_Api.Models.Entities.Auth;
using My_Social_Secure_Api.Models.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace My_Social_Secure_Api.Services.LoginTracking;

public class LoginHistoryService : ILoginHistoryService
{
    private readonly ApplicationDbContext _dbContext;
    private readonly ILogger<LoginHistoryService> _logger;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public LoginHistoryService(
        ApplicationDbContext dbContext,
        ILogger<LoginHistoryService> logger,
        IHttpContextAccessor httpContextAccessor)
    {
        _dbContext = dbContext;
        _logger = logger;
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task RecordLoginAsync(ApplicationUser user, string ip, string device, string location)
    {
        var correlationId = _httpContextAccessor?.HttpContext?.Items["X-Correlation-ID"]?.ToString();
        _logger.LogInformation("RecordLoginAsync started. CorrelationId: {CorrelationId}", correlationId);

        try
        {
            ValidateUser(user);

            var record = CreateLoginRecord(user, ip, device, location);

            await SaveLoginRecordAsync(record);

            _logger.LogInformation("Login recorded for user {UserId}", user.Id);
        }
        catch (ArgumentNullException ex)
        {
            _logger.LogError(ex, "Missing required argument when recording login. UserId: {UserId}", user?.Id);
        }
        catch (ArgumentException ex)
        {
            _logger.LogError(ex, "Invalid argument when recording login. UserId: {UserId}", user?.Id);
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogError(ex, "Invalid operation during login recording. UserId: {UserId}", user?.Id);
        }
        catch (DbUpdateConcurrencyException ex)
        {
            _logger.LogError(ex, "Concurrency error while recording login. UserId: {UserId}", user?.Id);
        }
        catch (DbUpdateException ex)
        {
            _logger.LogError(ex, "Database error while saving login record. UserId: {UserId}", user?.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error while recording login. UserId: {UserId}", user?.Id);
        }
    }

    private void ValidateUser(ApplicationUser user)
    {
        if (user == null)
        {
            _logger.LogError("User is null when trying to record login.");
            throw new ArgumentNullException(nameof(user));
        }
    }

    private LoginHistoryModel CreateLoginRecord(ApplicationUser user, string ip, string device, string location)
    {
        return new LoginHistoryModel
        {
            UserId = user.Id,
            IpAddress = ip,
            Device = device,
            Location = location,
            LoginTimeUtc = DateTime.UtcNow
        };
    }

    private async Task SaveLoginRecordAsync(LoginHistoryModel record)
    {
        _dbContext.LoginHistories.Add(record);
        await _dbContext.SaveChangesAsync();
    }
}
