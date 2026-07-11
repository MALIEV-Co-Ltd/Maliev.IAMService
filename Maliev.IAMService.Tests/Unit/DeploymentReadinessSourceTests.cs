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

        Assert.Contains("<ServiceDefaultsVersion Condition=\"'$(ServiceDefaultsVersion)' == ''\">1.0.81-alpha</ServiceDefaultsVersion>", buildProps, StringComparison.Ordinal);
        Assert.Contains("<MessagingContractsVersion Condition=\"'$(MessagingContractsVersion)' == ''\">1.0.91-alpha</MessagingContractsVersion>", buildProps, StringComparison.Ordinal);
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
        Assert.Contains("ARG SERVICE_DEFAULTS_VERSION=1.0.81-alpha", dockerfile, StringComparison.Ordinal);
        Assert.Contains("ARG MESSAGING_CONTRACTS_VERSION=1.0.91-alpha", dockerfile, StringComparison.Ordinal);
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
            Assert.Contains("-p:ServiceDefaultsVersion=1.0.81-alpha", workflow, StringComparison.Ordinal);
            Assert.Contains("-p:MessagingContractsVersion=1.0.91-alpha", workflow, StringComparison.Ordinal);
            Assert.Contains("needs: build-and-test", workflow, StringComparison.Ordinal);
            Assert.DoesNotContain("sed -i", workflow, StringComparison.Ordinal);
            Assert.DoesNotContain("1.0.*", workflow, StringComparison.Ordinal);
        }
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

        Assert.Contains("ref: 0bcd4c704d842211c5ff9bd6b9c4b3aacfcbd8e7", workflow, StringComparison.Ordinal);
        Assert.Contains("ref: 7121d57705fc1eff6c7ebb6a69e33e9c26ebfccc", workflow, StringComparison.Ordinal);
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

        Assert.Contains("readonly messaging_commit=\"0bcd4c704d842211c5ff9bd6b9c4b3aacfcbd8e7\"", packageScript, StringComparison.Ordinal);
        Assert.Contains("readonly aspire_commit=\"7121d57705fc1eff6c7ebb6a69e33e9c26ebfccc\"", packageScript, StringComparison.Ordinal);
        Assert.Contains("readonly messaging_version=\"1.0.91-alpha\"", packageScript, StringComparison.Ordinal);
        Assert.Contains("readonly service_defaults_version=\"1.0.81-alpha\"", packageScript, StringComparison.Ordinal);
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
