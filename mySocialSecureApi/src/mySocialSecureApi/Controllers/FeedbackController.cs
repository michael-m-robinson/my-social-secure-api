using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using My_Social_Secure_Api.Interfaces.Services.Feedback;
using My_Social_Secure_Api.Models.Dtos.Common;
using My_Social_Secure_Api.Models.Dtos.Feedback;
using System.Security.Claims;
using My_Social_Secure_Api.Models.Common;

namespace My_Social_Secure_Api.Controllers;

[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public class FeedbackController(
    IFeedbackService feedbackService,
    IHttpContextAccessor httpContextAccessor)
    : ControllerBase
{
    private readonly IFeedbackService _feedbackService = feedbackService;
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;

    private string CorrelationId =>
        _httpContextAccessor.HttpContext?.Items["X-Correlation-ID"]?.ToString() ?? "none";

    [HttpGet("all")]
    [Authorize(Policy = "CanModerateFeedback")]
    [ProducesResponseType(typeof(ApiResponse<FeedbackListDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> GetFeedback()
    {
        Response.Headers["X-Correlation-ID"] = CorrelationId;
        var result = await _feedbackService.GetFeedbackAsync();
        return StatusCode(result.Success ? 200 : 500, result);
    }

    [HttpGet("{id:guid}")]
    [Authorize(Policy = "CanModerateFeedback")]
    [ProducesResponseType(typeof(ApiResponse<FeedbackDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> GetById(Guid id)
    {
        Response.Headers["X-Correlation-ID"] = CorrelationId;
        var result = await _feedbackService.GetByIdAsync(id);
        return StatusCode(result.Success ? 200 : 404, result);
    }


    [HttpPost("submit")]
    [Authorize(Policy = "CanSubmitFeedback")]
    [ProducesResponseType(typeof(ApiResponse<OperationDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Submit([FromBody] CreateFeedbackDto dto)
    {
        Response.Headers["X-Correlation-ID"] = CorrelationId;
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? string.Empty;
        var result = await _feedbackService.SubmitAsync(dto, userId);
        return StatusCode(result.Success ? 200 : 400, result);
    }

    [HttpDelete("{feedbackId:guid}")]
    [Authorize(Policy = "CanModerateFeedback")]
    [ProducesResponseType(typeof(ApiResponse<OperationDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> DeleteFeedback(Guid feedbackId)
    {
        Response.Headers["X-Correlation-ID"] = CorrelationId;
        var result = await _feedbackService.DeleteFeedbackAsync(feedbackId);
        return StatusCode(result.Success ? 200 : 404, result);
    }
}
