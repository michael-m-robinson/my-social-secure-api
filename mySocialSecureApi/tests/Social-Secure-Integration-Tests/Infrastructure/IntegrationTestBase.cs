namespace Social_Secure_Integration_Tests.Infrastructure;

public abstract class IntegrationTestBase(CustomWebApplicationFactory factory)
    : IClassFixture<CustomWebApplicationFactory>
{
    protected readonly HttpClient Client = factory.CreateClient();
    protected readonly CustomWebApplicationFactory Factory = factory;
}