using System.Text.RegularExpressions;

namespace Maliev.IAMService.Tests.Unit;

/// <summary>
/// Guards the deterministic shared-library and public pull-request validation boundaries.
/// </summary>
public sealed partial class DeploymentReadinessSourceTests
{
    /// <summary>
    /// Verifies package-mode builds use the reviewed shared-library releases everywhere.
    /// </summary>
    [Fact]
    public void PackageModePinsReviewedSharedLibrariesAcrossBuildBoundaries()
    {
        string root = FindRepoRoot();
        string buildProps = File.ReadAllText(Path.Combine(root, "Directory.Build.props"));
        string dockerfile = File.ReadAllText(Path.Combine(root, "Maliev.IAMService.Api", "Dockerfile"));

        Assert.Contains("<ServiceDefaultsVersion Condition=\"'$(ServiceDefaultsVersion)' == ''\">1.0.86-alpha</ServiceDefaultsVersion>", buildProps, StringComparison.Ordinal);
        Assert.Contains("<MessagingContractsVersion Condition=\"'$(MessagingContractsVersion)' == ''\">1.0.94-alpha</MessagingContractsVersion>", buildProps, StringComparison.Ordinal);
        Assert.DoesNotContain("<SharedLibraryVersion", buildProps, StringComparison.Ordinal);
        Assert.DoesNotContain("1.0.*", buildProps, StringComparison.Ordinal);

        foreach (string projectPath in Directory.GetFiles(root, "*.csproj", SearchOption.AllDirectories))
        {
            if (projectPath.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase) ||
                projectPath.Contains($"{Path.DirectorySeparatorChar}.ci-sources{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string project = File.ReadAllText(projectPath);
            Assert.DoesNotContain("$(SharedLibraryVersion)", project, StringComparison.Ordinal);

            if (project.Contains("PackageReference Include=\"Maliev.Aspire.ServiceDefaults\"", StringComparison.Ordinal))
            {
                Assert.Contains("Version=\"$(ServiceDefaultsVersion)\"", project, StringComparison.Ordinal);
            }

            if (project.Contains("PackageReference Include=\"Maliev.MessagingContracts\"", StringComparison.Ordinal))
            {
                Assert.Contains("Version=\"$(MessagingContractsVersion)\"", project, StringComparison.Ordinal);
            }
        }

        Assert.Contains("COPY [\"Directory.Build.props\", \".\"]", dockerfile, StringComparison.Ordinal);
        Assert.Contains("ARG dependency_restore_stage=restore-private", dockerfile, StringComparison.Ordinal);
        Assert.Contains("FROM build-base AS restore-local", dockerfile, StringComparison.Ordinal);
        Assert.Contains("--configfile \"NuGet.PRValidation.Config\"", dockerfile, StringComparison.Ordinal);
        Assert.Contains("/p:GITHUB_ACTIONS=true", dockerfile, StringComparison.Ordinal);
        Assert.Contains("ARG SERVICE_DEFAULTS_VERSION=1.0.86-alpha", dockerfile, StringComparison.Ordinal);
        Assert.Contains("ARG MESSAGING_CONTRACTS_VERSION=1.0.94-alpha", dockerfile, StringComparison.Ordinal);
        Assert.Contains("/p:ServiceDefaultsVersion=\"$SERVICE_DEFAULTS_VERSION\"", dockerfile, StringComparison.Ordinal);
        Assert.Contains("/p:MessagingContractsVersion=\"$MESSAGING_CONTRACTS_VERSION\"", dockerfile, StringComparison.Ordinal);
        Assert.Contains("id=nuget_username,required=true", dockerfile, StringComparison.Ordinal);
        Assert.Contains("id=nuget_password,required=true", dockerfile, StringComparison.Ordinal);
        Assert.Contains("--no-restore", dockerfile, StringComparison.Ordinal);
        Assert.DoesNotContain("HEALTHCHECK", dockerfile, StringComparison.Ordinal);

        string validationWorkflow = File.ReadAllText(Path.Combine(root, ".github", "workflows", "_validate.yml"));
        Assert.DoesNotContain("GITHUB_ACTIONS=true", validationWorkflow, StringComparison.Ordinal);
        Assert.DoesNotContain("ServiceDefaultsVersion", validationWorkflow, StringComparison.Ordinal);
        Assert.DoesNotContain("MessagingContractsVersion", validationWorkflow, StringComparison.Ordinal);
        Assert.DoesNotContain("1.0.*", validationWorkflow, StringComparison.Ordinal);
    }

    /// <summary>
    /// Verifies reusable build callers grant the package permission required by the called workflow.
    /// </summary>
    [Theory]
    [InlineData("ci-develop.yml")]
    [InlineData("ci-staging.yml")]
    [InlineData("ci-main.yml")]
    public void ReusableValidationCallerUsesReadOnlyGate(string workflowName)
    {
        string root = FindRepoRoot();
        string workflow = File.ReadAllText(Path.Combine(root, ".github", "workflows", workflowName))
            .Replace("\r\n", "\n", StringComparison.Ordinal);

        Assert.Contains("uses: ./.github/workflows/_validate.yml", workflow, StringComparison.Ordinal);
        Assert.Contains("permissions:\n  contents: read", workflow, StringComparison.Ordinal);
        Assert.DoesNotContain("packages: read", workflow, StringComparison.Ordinal);
    }

    /// <summary>
    /// Verifies untrusted pull requests reconstruct immutable packages without credentials.
    /// </summary>
    [Fact]
    public void PullRequestValidationReconstructsExactDependenciesWithoutCredentials()
    {
        string root = FindRepoRoot();
        string pullRequestWorkflow = File.ReadAllText(Path.Combine(root, ".github", "workflows", "pr-validation.yml"));
        string validationWorkflow = File.ReadAllText(Path.Combine(root, ".github", "workflows", "_validate.yml"));
        string packageScript = File.ReadAllText(Path.Combine(root, "scripts", "prepare-iam-ci-packages.sh"));
        string validationConfig = File.ReadAllText(Path.Combine(root, "nuget.validation.config"));
        string productionConfig = File.ReadAllText(Path.Combine(root, "nuget.config"));

        Assert.Contains("pull_request:", pullRequestWorkflow, StringComparison.Ordinal);
        Assert.DoesNotContain("pull_request_target", pullRequestWorkflow, StringComparison.Ordinal);
        Assert.Contains("contents: read", pullRequestWorkflow, StringComparison.Ordinal);
        Assert.Contains("uses: ./.github/workflows/_validate.yml", pullRequestWorkflow, StringComparison.Ordinal);

        Assert.Contains("ref: 71d11dc093fb34ab41263d395c45629203cdbf18", validationWorkflow, StringComparison.Ordinal);
        Assert.Contains("ref: fb457bde0f3a0e5a01f767c88b942b2ccb8d7c61", validationWorkflow, StringComparison.Ordinal);
        Assert.Contains("--configfile nuget.validation.config", validationWorkflow, StringComparison.Ordinal);
        Assert.Contains("dotnet format Maliev.IAMService.slnx --verify-no-changes", validationWorkflow, StringComparison.Ordinal);
        Assert.Contains("dotnet build Maliev.IAMService.slnx --configuration Release", validationWorkflow, StringComparison.Ordinal);
        Assert.Contains("dotnet test Maliev.IAMService.slnx --configuration Release", validationWorkflow, StringComparison.Ordinal);
        Assert.Contains("package --vulnerable --include-transitive --no-restore", validationWorkflow, StringComparison.Ordinal);
        Assert.DoesNotContain("GITHUB_ACTIONS=true", validationWorkflow, StringComparison.Ordinal);
        Assert.DoesNotContain("docker", validationWorkflow, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("argocd", validationWorkflow, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("kubectl", validationWorkflow, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(UnpinnedActionRegex().Matches(validationWorkflow).Select(match => match.Value));

        Assert.Contains("readonly messaging_commit=\"71d11dc093fb34ab41263d395c45629203cdbf18\"", packageScript, StringComparison.Ordinal);
        Assert.Contains("readonly aspire_commit=\"fb457bde0f3a0e5a01f767c88b942b2ccb8d7c61\"", packageScript, StringComparison.Ordinal);
        Assert.Contains("readonly messaging_version=\"1.0.94-alpha\"", packageScript, StringComparison.Ordinal);
        Assert.Contains("readonly service_defaults_version=\"1.0.86-alpha\"", packageScript, StringComparison.Ordinal);
        Assert.Contains("dotnet restore \"$generator_project\" --configfile \"$ci_nuget_config\"", packageScript, StringComparison.Ordinal);
        Assert.Contains("--configuration Release --no-restore", packageScript, StringComparison.Ordinal);
        Assert.Contains("SHA256SUMS.txt", packageScript, StringComparison.Ordinal);
        Assert.DoesNotContain("--source", packageScript, StringComparison.Ordinal);

        Assert.DoesNotContain("nuget.pkg.github.com", validationConfig, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("packageSourceCredentials", validationConfig, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("<clear />", validationConfig, StringComparison.Ordinal);
        Assert.Contains("https://api.nuget.org/v3/index.json", validationConfig, StringComparison.Ordinal);
        Assert.Contains("<packageSourceMapping>", productionConfig, StringComparison.Ordinal);
        Assert.Contains("<packageSource key=\"github\">", productionConfig, StringComparison.Ordinal);
    }

    [GeneratedRegex(@"uses:\s+[^\s@]+@(?![0-9a-f]{40}(?:\s|$))[^\s]+", RegexOptions.CultureInvariant)]
    private static partial Regex UnpinnedActionRegex();

    private static string FindRepoRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Maliev.IAMService.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate the IAMService repository root.");
    }

}
