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

        foreach (string workflowName in new[] { "ci-develop.yml", "ci-staging.yml", "ci-main.yml" })
        {
            string workflow = File.ReadAllText(Path.Combine(root, ".github", "workflows", workflowName));
            Assert.Contains("uses: ./.github/workflows/_build-and-test.yml", workflow, StringComparison.Ordinal);
            Assert.Contains("-p:ServiceDefaultsVersion=1.0.86-alpha", workflow, StringComparison.Ordinal);
            Assert.Contains("-p:MessagingContractsVersion=1.0.94-alpha", workflow, StringComparison.Ordinal);
            Assert.Contains("needs: build-and-test", workflow, StringComparison.Ordinal);
            Assert.DoesNotContain("sed -i", workflow, StringComparison.Ordinal);
            Assert.DoesNotContain("1.0.*", workflow, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// Verifies reusable build callers grant the package permission required by the called workflow.
    /// </summary>
    [Theory]
    [InlineData("ci-develop.yml")]
    [InlineData("ci-staging.yml")]
    [InlineData("ci-main.yml")]
    public void ReusableBuildWorkflowCallerGrantsRequiredPermissions(string workflowName)
    {
        string root = FindRepoRoot();
        string workflow = File.ReadAllText(Path.Combine(root, ".github", "workflows", workflowName))
            .Replace("\r\n", "\n", StringComparison.Ordinal);
        string callerJob = ExtractWorkflowJob(workflow, "build-and-test");

        Assert.Contains("uses: ./.github/workflows/_build-and-test.yml", callerJob, StringComparison.Ordinal);
        Assert.Contains("    permissions:\n      contents: read\n      packages: read", callerJob, StringComparison.Ordinal);
    }

    /// <summary>
    /// Verifies untrusted pull requests reconstruct immutable packages without credentials.
    /// </summary>
    [Fact]
    public void PullRequestValidationReconstructsExactDependenciesWithoutCredentials()
    {
        string root = FindRepoRoot();
        string workflow = File.ReadAllText(Path.Combine(root, ".github", "workflows", "pr-validation.yml"));
        string packageScript = File.ReadAllText(Path.Combine(root, "scripts", "prepare-iam-ci-packages.sh"));
        string validationConfig = File.ReadAllText(Path.Combine(root, "NuGet.PRValidation.Config"));
        string productionConfig = File.ReadAllText(Path.Combine(root, "nuget.config"));

        Assert.Contains("pull_request:", workflow, StringComparison.Ordinal);
        Assert.DoesNotContain("pull_request_target", workflow, StringComparison.Ordinal);
        Assert.Contains("permissions:", workflow, StringComparison.Ordinal);
        Assert.Contains("contents: read", workflow, StringComparison.Ordinal);
        Assert.DoesNotContain("packages: read", workflow, StringComparison.Ordinal);
        Assert.DoesNotContain("secrets:", workflow, StringComparison.Ordinal);
        Assert.DoesNotContain("GITOPS_PAT", workflow, StringComparison.Ordinal);
        Assert.DoesNotContain("github.token", workflow, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("NUGET_USERNAME", workflow, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("NUGET_PASSWORD", workflow, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("concurrency:", workflow, StringComparison.Ordinal);
        Assert.Contains("cancel-in-progress: true", workflow, StringComparison.Ordinal);
        Assert.Contains("NUGET_PACKAGES: ${{ github.workspace }}/.ci-nuget/packages", workflow, StringComparison.Ordinal);

        Assert.Contains("ref: 71d11dc093fb34ab41263d395c45629203cdbf18", workflow, StringComparison.Ordinal);
        Assert.Contains("ref: fb457bde0f3a0e5a01f767c88b942b2ccb8d7c61", workflow, StringComparison.Ordinal);
        Assert.Contains("include-hidden-files: true", workflow, StringComparison.Ordinal);
        Assert.Contains("overwrite: true", workflow, StringComparison.Ordinal);
        Assert.Contains("github.run_attempt", workflow, StringComparison.Ordinal);
        Assert.Contains("artifact-digest", workflow, StringComparison.Ordinal);
        Assert.Contains("sha256sum --check SHA256SUMS.txt", workflow, StringComparison.Ordinal);
        Assert.Contains("--configfile NuGet.PRValidation.Config", workflow, StringComparison.Ordinal);
        Assert.Contains("dotnet build Maliev.IAMService.slnx", workflow, StringComparison.Ordinal);
        Assert.Contains("dotnet test Maliev.IAMService.slnx", workflow, StringComparison.Ordinal);
        Assert.Contains("--configuration Release", workflow, StringComparison.Ordinal);
        Assert.Contains("--no-build", workflow, StringComparison.Ordinal);
        Assert.Contains("--no-restore", workflow, StringComparison.Ordinal);
        Assert.Contains("package --include-transitive --vulnerable --no-restore --configfile NuGet.PRValidation.Config", workflow, StringComparison.Ordinal);
        Assert.Contains("dependency_restore_stage=restore-local", workflow, StringComparison.Ordinal);
        Assert.Contains("/iam/liveness", workflow, StringComparison.Ordinal);
        Assert.Contains("postgres:18-alpine", workflow, StringComparison.Ordinal);
        Assert.Contains("format: cyclonedx", workflow, StringComparison.Ordinal);
        Assert.Contains("severity: HIGH,CRITICAL", workflow, StringComparison.Ordinal);
        Assert.Contains("exit-code: \"1\"", workflow, StringComparison.Ordinal);
        Assert.DoesNotContain("argocd", workflow, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("kubectl", workflow, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(UnpinnedActionRegex().Matches(workflow).Select(match => match.Value));

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
        Assert.Contains("<packageSourceMapping>", validationConfig, StringComparison.Ordinal);
        Assert.Contains("<package pattern=\"Maliev.*\" />", validationConfig, StringComparison.Ordinal);
        Assert.Contains("<packageSourceMapping>", productionConfig, StringComparison.Ordinal);
        Assert.Contains("<packageSource key=\"github\">", productionConfig, StringComparison.Ordinal);
    }

    [GeneratedRegex(@"uses:\s+[^\s@]+@(?![0-9a-f]{40}(?:\s|$))[^\s]+", RegexOptions.CultureInvariant)]
    private static partial Regex UnpinnedActionRegex();

    [GeneratedRegex(@"(?m)^  [A-Za-z0-9_-]+:\n", RegexOptions.CultureInvariant)]
    private static partial Regex WorkflowJobHeaderRegex();

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

    private static string ExtractWorkflowJob(string workflow, string jobName)
    {
        string marker = $"  {jobName}:\n";
        int jobStart = workflow.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(jobStart >= 0, $"Workflow job '{jobName}' was not found.");

        Match nextJob = WorkflowJobHeaderRegex().Match(workflow, jobStart + marker.Length);
        return nextJob.Success ? workflow[jobStart..nextJob.Index] : workflow[jobStart..];
    }
}
