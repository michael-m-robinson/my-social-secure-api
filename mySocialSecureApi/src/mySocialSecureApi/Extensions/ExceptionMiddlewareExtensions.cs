using System.Text.Json;
using Microsoft.AspNetCore.Diagnostics;
using My_Social_Secure_Api.Exceptions;

namespace My_Social_Secure_Api.Extensions;

public static class ExceptionMiddlewareExtensions
{
    public static void ConfigureExceptionHandler(this IApplicationBuilder app, ILoggerFactory loggerFactory)
    {
        app.UseExceptionHandler(appError =>
        {
            appError.Run(async context =>
            {
                var logger = loggerFactory.CreateLogger("GlobalExceptionHandler");
                var contextFeature = context.Features.Get<IExceptionHandlerFeature>();

                context.Response.ContentType = "application/json";

                if (contextFeature?.Error is UnauthorizedAppException)
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    await context.Response.WriteAsync(JsonSerializer.Serialize(new
                    {
                        title = "Unauthorized",
                        status = 401,
                        detail = contextFeature.Error.Message
                    }));
                }
                else if (contextFeature?.Error is NotFoundException)
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    await context.Response.WriteAsync(JsonSerializer.Serialize(new
                    {
                        title = "Not Found",
                        status = 404,
                        detail = contextFeature.Error.Message
                    }));
                }
                else
                {
                    logger.LogError(contextFeature?.Error, "Unhandled exception");

                    context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                    await context.Response.WriteAsync(JsonSerializer.Serialize(new
                    {
                        title = "Internal Server Error",
                        status = 500,
                        detail = "An unexpected error occurred."
                    }));
                }
            });
        });
    }
}