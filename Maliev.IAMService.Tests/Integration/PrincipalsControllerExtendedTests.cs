using System.Net;
using System.Net.Http.Json;
using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Application.DTOs.Responses;
using Maliev.IAMService.Tests.Testing;

namespace Maliev.IAMService.Tests.Integration;

public class PrincipalsControllerExtendedTests : BaseIntegrationTest
{
    public PrincipalsControllerExtendedTests(TestWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task GetPrincipals_WithPagination_ReturnsOk()
    {
        await CleanDatabaseAsync();

        for (int i = 0; i < 5; i++)
        {
            await Client.PostAsJsonAsync("/iam/v1/principals", new CreatePrincipalRequest
            {
                PrincipalType = "user",
                Email = $"page-test-{i}@example.com"
            });
        }

        var response = await Client.GetAsync("/iam/v1/principals?skip=0&take=2");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task GetPrincipals_FilterByType_ReturnsOk()
    {
        await CleanDatabaseAsync();

        await Client.PostAsJsonAsync("/iam/v1/principals", new CreatePrincipalRequest
        {
            PrincipalType = "user",
            Email = "user-type@example.com"
        });

        var response = await Client.GetAsync("/iam/v1/principals?principalType=user");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
