using Maliev.IAMService.Application.Workloads;

namespace Maliev.IAMService.Tests.Unit;

public sealed class WorkloadAccessProfileCatalogTests
{
    [Fact]
    public void Constructor_WildcardPermission_RejectsProfile()
    {
        var profile = new WorkloadAccessProfile("unsafe", 1, "roles.workloads.unsafe.v1", ["*"]);

        Assert.Throws<ArgumentException>(() => new WorkloadAccessProfileCatalog([profile]));
    }

    [Fact]
    public void Constructor_PlatformOwnerRole_RejectsProfile()
    {
        var profile = new WorkloadAccessProfile("unsafe", 1, "roles.platform.owner", ["iam.auth.resolve-permissions"]);

        Assert.Throws<ArgumentException>(() => new WorkloadAccessProfileCatalog([profile]));
    }

    [Theory]
    [InlineData("roles.auth.workload")]
    [InlineData("roles.workloads.other-service.v1")]
    [InlineData("roles.workloads.auth-service.v2")]
    public void Constructor_NonCanonicalWorkloadRole_RejectsProfile(string roleId)
    {
        var profile = new WorkloadAccessProfile("auth-service", 1, roleId, ["iam.auth.resolve-permissions"]);

        Assert.Throws<ArgumentException>(() => new WorkloadAccessProfileCatalog([profile]));
    }

    [Theory]
    [InlineData("-contact-service")]
    [InlineData("contact-service-")]
    [InlineData("contact--service")]
    [InlineData("-")]
    public void Constructor_NonCanonicalHyphenatedWorkloadId_RejectsProfile(string workloadId)
    {
        var profile = new WorkloadAccessProfile(
            workloadId,
            1,
            $"roles.workloads.{workloadId}.v1",
            ["country.countries.read"]);

        Assert.Throws<ArgumentException>(() => new WorkloadAccessProfileCatalog([profile]));
    }

    [Fact]
    public void Constructor_WorkloadIdExceedsPersistenceLimit_RejectsProfile()
    {
        var workloadId = new string('a', 101);
        var profile = new WorkloadAccessProfile(
            workloadId,
            1,
            $"roles.workloads.{workloadId}.v1",
            ["country.countries.read"]);

        Assert.Throws<ArgumentException>(() => new WorkloadAccessProfileCatalog([profile]));
    }

    [Fact]
    public void Get_AuthServiceVersionOne_ReturnsExactLeastPrivilegePermissions()
    {
        var profile = WorkloadAccessProfileCatalog.Default.Get("auth-service", 1);

        Assert.Equal("roles.workloads.auth-service.v1", profile.RoleId);
        Assert.Equal(["iam.auth.resolve-permissions"], profile.Permissions);
    }

    [Fact]
    public void Get_ContactServiceVersionOne_ReturnsExactLeastPrivilegePermissions()
    {
        var profile = WorkloadAccessProfileCatalog.Default.Get("contact-service", 1);

        Assert.Equal("roles.workloads.contact-service.v1", profile.RoleId);
        Assert.Equal(["country.countries.read"], profile.Permissions);
        var grant = Assert.Single(profile.AdditionalGrants);
        Assert.Equal("roles.workloads.contact-service.v1.upload-contacts", grant.RoleId);
        Assert.Equal("folders/contacts", grant.ResourcePath);
        Assert.Equal(
            ["upload.files.upload", "upload.files.download", "upload.files.delete"],
            grant.Permissions);
    }

    [Fact]
    public void Get_SearchServiceVersionOne_ReturnsOnlyLivePermissionCheckAuthority()
    {
        var profile = WorkloadAccessProfileCatalog.Default.Get("search-service", 1);

        Assert.Equal("roles.workloads.search-service.v1", profile.RoleId);
        Assert.Equal(["iam.auth.check-permission"], profile.Permissions);
        Assert.Empty(profile.AdditionalGrants);
        Assert.DoesNotContain("iam.auth.resolve-permissions", profile.Permissions);
    }

    [Fact]
    public void Get_RegistryServiceVersionOne_ReturnsOnlyLivePermissionCheckAuthority()
    {
        var profile = WorkloadAccessProfileCatalog.Default.Get("registry-service", 1);

        Assert.Equal("roles.workloads.registry-service.v1", profile.RoleId);
        Assert.Equal(["iam.auth.check-permission"], profile.Permissions);
        Assert.Empty(profile.AdditionalGrants);
        Assert.DoesNotContain("iam.auth.resolve-permissions", profile.Permissions);
    }

    [Fact]
    public void Get_CountryServiceVersionOne_ReturnsOnlyLivePermissionCheckAuthority()
    {
        var profile = WorkloadAccessProfileCatalog.Default.Get("country-service", 1);

        Assert.Equal("roles.workloads.country-service.v1", profile.RoleId);
        Assert.Equal(["iam.auth.check-permission"], profile.Permissions);
        Assert.Empty(profile.AdditionalGrants);
        Assert.DoesNotContain("iam.auth.resolve-permissions", profile.Permissions);
    }

    [Fact]
    public void Get_CurrencyServiceVersionOne_ReturnsOnlyLivePermissionCheckAuthority()
    {
        var profile = WorkloadAccessProfileCatalog.Default.Get("currency-service", 1);

        Assert.Equal("roles.workloads.currency-service.v1", profile.RoleId);
        Assert.Equal(["iam.auth.check-permission"], profile.Permissions);
        Assert.Empty(profile.AdditionalGrants);
        Assert.DoesNotContain("iam.auth.resolve-permissions", profile.Permissions);
    }

    [Fact]
    public void Get_AccountingServiceVersionOne_ReturnsOnlyLivePermissionCheckAuthority()
    {
        var profile = WorkloadAccessProfileCatalog.Default.Get("accounting-service", 1);

        Assert.Equal("roles.workloads.accounting-service.v1", profile.RoleId);
        Assert.Equal(["iam.auth.check-permission"], profile.Permissions);
        Assert.Empty(profile.AdditionalGrants);
        Assert.DoesNotContain("iam.auth.resolve-permissions", profile.Permissions);
    }

    [Fact]
    public void Get_PricingServiceVersionOne_ReturnsExactLeastPrivilegeAuthority()
    {
        var profile = WorkloadAccessProfileCatalog.Default.Get("pricing-service", 1);

        Assert.Equal(new Guid("18181818-1818-1818-1818-181818181818"), profile.PrincipalId);
        Assert.Equal("roles.workloads.pricing-service.v1", profile.RoleId);
        Assert.Equal(
            [
                "iam.auth.check-permission",
                "material.materials.read",
                "job.jobs.read",
                "currency.rates.read"
            ],
            profile.Permissions);
        Assert.Empty(profile.AdditionalGrants);
        Assert.DoesNotContain("iam.auth.resolve-permissions", profile.Permissions);
        Assert.DoesNotContain(profile.Permissions, permission => permission.Contains('*', StringComparison.Ordinal));
        Assert.DoesNotContain(profile.Permissions, permission => permission.EndsWith(".write", StringComparison.Ordinal));
        Assert.DoesNotContain(profile.Permissions, permission => permission.EndsWith(".admin", StringComparison.Ordinal));
        Assert.DoesNotContain("roles.platform.owner", profile.RoleId, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Get_MaterialServiceVersionOne_ReturnsExactLeastPrivilegeAuthority()
    {
        var profile = WorkloadAccessProfileCatalog.Default.Get("material-service", 1);

        Assert.Equal(new Guid("19191919-1919-1919-1919-191919191919"), profile.PrincipalId);
        Assert.Equal("roles.workloads.material-service.v1", profile.RoleId);
        Assert.Equal(
            [
                "iam.auth.check-permission",
                "supplier.supplier-references.read"
            ],
            profile.Permissions);
        Assert.Empty(profile.AdditionalGrants);
        Assert.DoesNotContain("iam.auth.resolve-permissions", profile.Permissions);
        Assert.DoesNotContain(profile.Permissions, permission => permission.Contains('*', StringComparison.Ordinal));
        Assert.DoesNotContain(profile.Permissions, permission => permission.EndsWith(".write", StringComparison.Ordinal));
        Assert.DoesNotContain(profile.Permissions, permission => permission.EndsWith(".admin", StringComparison.Ordinal));
        Assert.DoesNotContain("supplier.suppliers.read", profile.Permissions);
        Assert.DoesNotContain("roles.platform.owner", profile.RoleId, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Get_LifecycleServiceVersionOne_ReturnsOnlyLivePermissionCheckAuthority()
    {
        var profile = WorkloadAccessProfileCatalog.Default.Get("lifecycle-service", 1);

        Assert.Equal(new Guid("20202020-2020-2020-2020-202020202020"), profile.PrincipalId);
        Assert.Equal("roles.workloads.lifecycle-service.v1", profile.RoleId);
        Assert.Equal(["iam.auth.check-permission"], profile.Permissions);
        Assert.Empty(profile.AdditionalGrants);
        Assert.DoesNotContain("iam.auth.resolve-permissions", profile.Permissions);
        Assert.DoesNotContain(profile.Permissions, permission => permission.Contains('*', StringComparison.Ordinal));
        Assert.DoesNotContain("roles.platform.owner", profile.RoleId, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Constructor_DuplicateCanonicalPrincipalIds_Throws()
    {
        var principalId = Guid.Parse("18181818-1818-1818-1818-181818181818");
        var first = new WorkloadAccessProfile(
            "pricing-service",
            1,
            "roles.workloads.pricing-service.v1",
            ["iam.auth.check-permission"])
        {
            PrincipalId = principalId
        };
        var second = new WorkloadAccessProfile(
            "quotation-service",
            1,
            "roles.workloads.quotation-service.v1",
            ["iam.auth.check-permission"])
        {
            PrincipalId = principalId
        };

        Assert.Throws<ArgumentException>(() => new WorkloadAccessProfileCatalog([first, second]));
    }

    [Fact]
    public void Constructor_SameWorkloadVersionsReuseCanonicalPrincipalId_Succeeds()
    {
        var principalId = Guid.Parse("18181818-1818-1818-1818-181818181818");
        var first = new WorkloadAccessProfile(
            "pricing-service",
            1,
            "roles.workloads.pricing-service.v1",
            ["iam.auth.check-permission"])
        {
            PrincipalId = principalId
        };
        var second = new WorkloadAccessProfile(
            "pricing-service",
            2,
            "roles.workloads.pricing-service.v2",
            ["iam.auth.check-permission"])
        {
            PrincipalId = principalId
        };

        var catalog = new WorkloadAccessProfileCatalog([first, second]);

        Assert.Equal(principalId, catalog.Get("pricing-service", 1).PrincipalId);
        Assert.Equal(principalId, catalog.Get("pricing-service", 2).PrincipalId);
    }

    [Fact]
    public void Constructor_SameWorkloadVersionsUseDifferentCanonicalPrincipalIds_Throws()
    {
        var first = new WorkloadAccessProfile(
            "pricing-service",
            1,
            "roles.workloads.pricing-service.v1",
            ["iam.auth.check-permission"])
        {
            PrincipalId = Guid.Parse("18181818-1818-1818-1818-181818181818")
        };
        var second = new WorkloadAccessProfile(
            "pricing-service",
            2,
            "roles.workloads.pricing-service.v2",
            ["iam.auth.check-permission"])
        {
            PrincipalId = Guid.Parse("19191919-1919-1919-1919-191919191919")
        };

        Assert.Throws<ArgumentException>(() => new WorkloadAccessProfileCatalog([first, second]));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Constructor_SameWorkloadVersionsMixCanonicalAndGeneratedPrincipalPolicies_Throws(
        bool canonicalProfileFirst)
    {
        var canonical = new WorkloadAccessProfile(
            "pricing-service",
            canonicalProfileFirst ? 1 : 2,
            $"roles.workloads.pricing-service.v{(canonicalProfileFirst ? 1 : 2)}",
            ["iam.auth.check-permission"])
        {
            PrincipalId = Guid.Parse("18181818-1818-1818-1818-181818181818")
        };
        var generated = new WorkloadAccessProfile(
            "pricing-service",
            canonicalProfileFirst ? 2 : 1,
            $"roles.workloads.pricing-service.v{(canonicalProfileFirst ? 2 : 1)}",
            ["iam.auth.check-permission"]);
        var profiles = canonicalProfileFirst
            ? new[] { canonical, generated }
            : new[] { generated, canonical };

        Assert.Throws<ArgumentException>(() => new WorkloadAccessProfileCatalog(profiles));
    }

    [Fact]
    public void Constructor_SourcePermissionListMutated_PreservesRegisteredProfile()
    {
        var permissions = new List<string> { "country.countries.read" };
        var catalog = new WorkloadAccessProfileCatalog(
        [
            new WorkloadAccessProfile(
                "contact-service",
                1,
                "roles.workloads.contact-service.v1",
                permissions)
        ]);

        permissions[0] = "country.countries.create";
        permissions.Add("*");

        var profile = catalog.Get("contact-service", 1);
        Assert.Equal(["country.countries.read"], profile.Permissions);
    }

    [Fact]
    public void Constructor_NestedGrantSourcesMutated_PreservesRegisteredProfile()
    {
        var grantPermissions = new List<string> { "upload.files.upload" };
        var grants = new List<WorkloadAccessGrant>
        {
            new("roles.workloads.contact-service.v1.upload-contacts", "folders/contacts", grantPermissions)
        };
        var catalog = new WorkloadAccessProfileCatalog(
        [
            new WorkloadAccessProfile(
                "contact-service",
                1,
                "roles.workloads.contact-service.v1",
                ["country.countries.read"])
            {
                AdditionalGrants = grants
            }
        ]);

        grantPermissions[0] = "upload.admin.all";
        grants.Clear();

        var profile = catalog.Get("contact-service", 1);
        var grant = Assert.Single(profile.AdditionalGrants);
        Assert.Equal(["upload.files.upload"], grant.Permissions);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("*")]
    [InlineData("/folders/contacts")]
    [InlineData("folders//contacts")]
    [InlineData("folders/contacts/")]
    [InlineData("folders/Contacts")]
    [InlineData("folders/-contacts")]
    [InlineData("folders/contacts-")]
    [InlineData("folders/contact--files")]
    [InlineData("folders/-")]
    public void Constructor_NonCanonicalAdditionalGrantPath_RejectsProfile(string? resourcePath)
    {
        var profile = CreateProfileWithGrant(
            "roles.workloads.contact-service.v1.upload-contacts",
            resourcePath!,
            ["upload.files.upload"]);

        Assert.Throws<ArgumentException>(() => new WorkloadAccessProfileCatalog([profile]));
    }

    [Theory]
    [InlineData("roles.workloads.contact-service.v1")]
    [InlineData("roles.workloads.contact-service.v1.Upload")]
    [InlineData("roles.workloads.contact-service.v1.upload.contacts")]
    [InlineData("roles.workloads.other-service.v1.upload-contacts")]
    [InlineData("roles.platform.owner")]
    [InlineData("roles.workloads.contact-service.v1.-upload")]
    [InlineData("roles.workloads.contact-service.v1.upload-")]
    [InlineData("roles.workloads.contact-service.v1.upload--contacts")]
    [InlineData("roles.workloads.contact-service.v1.-")]
    public void Constructor_NonCanonicalAdditionalGrantRole_RejectsProfile(string roleId)
    {
        var profile = CreateProfileWithGrant(roleId, "folders/contacts", ["upload.files.upload"]);

        Assert.Throws<ArgumentException>(() => new WorkloadAccessProfileCatalog([profile]));
    }

    [Fact]
    public void Constructor_DerivedAdditionalRoleIdExceedsPersistenceLimit_RejectsProfile()
    {
        const string baseRoleId = "roles.workloads.contact-service.v1";
        var suffix = new string('a', 255 - baseRoleId.Length);
        var roleId = $"{baseRoleId}.{suffix}";
        var profile = CreateProfileWithGrant(roleId, "folders/contacts", ["upload.files.upload"]);

        Assert.True(roleId.Length > 255);
        Assert.Throws<ArgumentException>(() => new WorkloadAccessProfileCatalog([profile]));
    }

    [Fact]
    public void Constructor_DuplicateOrGloballyGrantedAdditionalAuthority_RejectsProfile()
    {
        var duplicateRole = new WorkloadAccessProfile(
            "contact-service",
            1,
            "roles.workloads.contact-service.v1",
            ["country.countries.read"])
        {
            AdditionalGrants =
            [
                new("roles.workloads.contact-service.v1.upload-contacts", "folders/contacts", ["upload.files.upload"]),
                new("roles.workloads.contact-service.v1.upload-contacts", "folders/archive", ["upload.files.delete"])
            ]
        };
        var duplicatePermission = CreateProfileWithGrant(
            "roles.workloads.contact-service.v1.upload-contacts",
            "folders/contacts",
            ["upload.files.upload", "upload.files.upload"]);
        var globallyGrantedPermission = CreateProfileWithGrant(
            "roles.workloads.contact-service.v1.country-contacts",
            "folders/contacts",
            ["country.countries.read"]);

        Assert.Throws<ArgumentException>(() => new WorkloadAccessProfileCatalog([duplicateRole]));
        Assert.Throws<ArgumentException>(() => new WorkloadAccessProfileCatalog([duplicatePermission]));
        Assert.Throws<ArgumentException>(() => new WorkloadAccessProfileCatalog([globallyGrantedPermission]));
    }

    [Fact]
    public void Constructor_WildcardAdditionalAuthority_RejectsProfile()
    {
        var profile = CreateProfileWithGrant(
            "roles.workloads.contact-service.v1.upload-contacts",
            "folders/contacts",
            ["upload.files.*"]);

        Assert.Throws<ArgumentException>(() => new WorkloadAccessProfileCatalog([profile]));
    }

    private static WorkloadAccessProfile CreateProfileWithGrant(
        string roleId,
        string resourcePath,
        IReadOnlyList<string> permissions) =>
        new(
            "contact-service",
            1,
            "roles.workloads.contact-service.v1",
            ["country.countries.read"])
        {
            AdditionalGrants = [new WorkloadAccessGrant(roleId, resourcePath, permissions)]
        };
}
