using Maliev.IAMService.Api.Authorization;
using Maliev.IAMService.Tests.Testing;
using Xunit;

namespace Maliev.IAMService.Tests.Data;

[Collection("Integration Tests")]
public class DataCoverageTests
{
    private readonly TestWebApplicationFactory _factory;

    public DataCoverageTests(TestWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public void Permissions_Constants_Coverage()
    {
        Assert.Equal("iam.principals.list", IAMPermissions.PrincipalsList);
        Assert.Equal("iam.roles.list", IAMPermissions.RolesList);
    }
}
