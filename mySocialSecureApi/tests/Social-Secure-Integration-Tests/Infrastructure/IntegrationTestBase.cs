using Xunit.Abstractions;

namespace Social_Secure_Integration_Tests.Infrastructure;

public abstract class IntegrationTestBase(CustomWebApplicationFactory factory, ITestOutputHelper output)
    : IClassFixture<CustomWebApplicationFactory>
{
    protected readonly HttpClient Client = factory.CreateClient();
    protected readonly CustomWebApplicationFactory Factory = factory;
    protected readonly ITestOutputHelper Output = output;
}