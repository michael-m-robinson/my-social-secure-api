namespace My_Social_Secure_Api.Swagger;

using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;

public class AddCorrelationIdHeaderOperationFilter : IOperationFilter
{
    public void Apply(OpenApiOperation operation, OperationFilterContext context)
    {
        operation.Responses.TryAdd("200", new OpenApiResponse { Description = "Success" });

        foreach (var response in operation.Responses.Values)
        {
            response.Headers.Add("X-Correlation-ID", new OpenApiHeader
            {
                Description = "Correlation ID for tracing the request",
                Schema = new OpenApiSchema { Type = "string" }
            });
        }
    }
}