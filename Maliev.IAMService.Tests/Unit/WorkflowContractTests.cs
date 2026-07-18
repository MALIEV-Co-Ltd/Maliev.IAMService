namespace Maliev.IAMService.Tests.Unit;

/// <summary>
/// Guards the credential-free validation boundary used for the first main-branch promotion.
/// </summary>
public sealed class WorkflowContractTests
{
    private const string CheckoutSha = "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0";
    private const string SetupDotnetSha = "a98b56852c35b8e3190ac28c8c2271da59106c68";
    private const string AspireSha = "fb457bde0f3a0e5a01f767c88b942b2ccb8d7c61";
    private const string MessagingSha = "71d11dc093fb34ab41263d395c45629203cdbf18";

    private static readonly string Root = FindRoot();
    private static readonly string Workflows = Path.Combine(Root, ".github", "workflows");

    /// <summary>
    /// Pull requests must always execute the same read-only validation gate.
    /// </summary>
    [Fact]
    public void PullRequests_AlwaysUseReadOnlyReusableValidation()
    {
        var source = ReadWorkflow("pr-validation.yml");
        Assert.Contains("pull_request:", source, StringComparison.Ordinal);
        Assert.Contains("contents: read", source, StringComparison.Ordinal);
        Assert.Contains("uses: ./.github/workflows/_validate.yml", source, StringComparison.Ordinal);
        Assert.DoesNotContain("paths:", source, StringComparison.Ordinal);
        AssertSafe(source);
    }

    /// <summary>
    /// Every release-bearing ref must validate without publishing or deploying.
    /// </summary>
    [Theory]
    [InlineData("ci-main.yml", "main")]
    [InlineData("ci-develop.yml", "develop")]
    [InlineData("ci-staging.yml", "release/v*")]
    public void BranchAndTagWorkflows_AreValidationOnly(string file, string trigger)
    {
        var source = ReadWorkflow(file);
        Assert.Contains(trigger, source, StringComparison.Ordinal);
        Assert.Contains("uses: ./.github/workflows/_validate.yml", source, StringComparison.Ordinal);
        AssertSafe(source);
    }

    /// <summary>
    /// Validation resolves shared source from immutable public commits and NuGet.org only.
    /// </summary>
    [Fact]
    public void ReusableValidation_UsesImmutablePublicSharedSources()
    {
        var source = ReadWorkflow("_validate.yml");
        Assert.Contains("workflow_call:", source, StringComparison.Ordinal);
        Assert.Contains("name: validate", source, StringComparison.Ordinal);
        Assert.Contains($"actions/checkout@{CheckoutSha}", source, StringComparison.Ordinal);
        Assert.Contains($"actions/setup-dotnet@{SetupDotnetSha}", source, StringComparison.Ordinal);
        Assert.Contains($"ref: {AspireSha}", source, StringComparison.Ordinal);
        Assert.Contains($"ref: {MessagingSha}", source, StringComparison.Ordinal);
        Assert.Contains("dotnet-version: 10.0.x", source, StringComparison.Ordinal);
        Assert.Contains("--configfile nuget.validation.config", source, StringComparison.Ordinal);

        var nuget = File.ReadAllText(Path.Combine(Root, "nuget.validation.config"));
        Assert.Contains("<clear />", nuget, StringComparison.Ordinal);
        Assert.Contains("https://api.nuget.org/v3/index.json", nuget, StringComparison.Ordinal);
        Assert.DoesNotContain("nuget.pkg.github.com", nuget, StringComparison.OrdinalIgnoreCase);
        AssertSafe(source);
    }

    /// <summary>
    /// No active workflow may cross the validation/deployment boundary.
    /// </summary>
    [Fact]
    public void EveryWorkflow_ForbidsCredentialsAndDeploymentMutation()
    {
        foreach (var file in Directory.GetFiles(Workflows, "*.yml"))
        {
            AssertSafe(File.ReadAllText(file));
        }
    }

    private static void AssertSafe(string source)
    {
        foreach (var forbidden in new[]
        {
            "secrets.", "GITOPS_PAT", "GCP_SA_KEY", "NUGET_PASSWORD", "id-token: write",
            "credentials_json", "google-github-actions/auth", "gcloud auth", "docker push",
            "maliev-gitops", "kustomize edit", "git push origin", "gh pr create", "pull_request_target",
        })
        {
            Assert.DoesNotContain(forbidden, source, StringComparison.OrdinalIgnoreCase);
        }
    }

    private static string ReadWorkflow(string file)
    {
        var path = Path.Combine(Workflows, file);
        Assert.True(File.Exists(path), $"Required workflow is missing: {file}");
        return File.ReadAllText(path);
    }

    private static string FindRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Maliev.IAMService.slnx")))
            {
                return directory.FullName;
            }
        }

        throw new DirectoryNotFoundException("Could not locate IAMService repository root.");
    }
}
