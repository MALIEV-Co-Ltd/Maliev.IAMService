using Maliev.IAMService.Domain.Constants;
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

    [Fact]
    public void IAMPermissions_Arrays_AreNotEmpty()
    {
        Assert.NotEmpty(IAMPermissions.All);
        Assert.NotEmpty(IAMPermissions.ReadOnly);
        Assert.NotEmpty(IAMPermissions.Admin);
    }

    [Fact]
    public void IAMPermissions_All_ContainsAllPermissionGroups()
    {
        Assert.Contains(IAMPermissions.PrincipalsCreate, IAMPermissions.All);
        Assert.Contains(IAMPermissions.RolesCreate, IAMPermissions.All);
        Assert.Contains(IAMPermissions.PermissionsCreate, IAMPermissions.All);
        Assert.Contains(IAMPermissions.BindingsCreate, IAMPermissions.All);
        Assert.Contains(IAMPermissions.AuthCheckPermission, IAMPermissions.All);
        Assert.Contains(IAMPermissions.AuditRead, IAMPermissions.All);
    }

    [Fact]
    public void IAMPermissions_ReadOnly_DoesNotContainWritePermissions()
    {
        Assert.DoesNotContain(IAMPermissions.PrincipalsCreate, IAMPermissions.ReadOnly);
        Assert.DoesNotContain(IAMPermissions.RolesCreate, IAMPermissions.ReadOnly);
        Assert.Contains(IAMPermissions.PrincipalsRead, IAMPermissions.ReadOnly);
    }

    [Fact]
    public void IAMPermissions_Admin_ContainsWritePermissions()
    {
        Assert.Contains(IAMPermissions.PrincipalsCreate, IAMPermissions.Admin);
        Assert.Contains(IAMPermissions.RolesCreate, IAMPermissions.Admin);
        Assert.Contains(IAMPermissions.BindingsCreate, IAMPermissions.Admin);
    }
}
