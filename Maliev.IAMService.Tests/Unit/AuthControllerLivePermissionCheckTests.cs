using System.Diagnostics.Metrics;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Maliev.IAMService.Api.Controllers;
using Maliev.IAMService.Api.Authorization;
using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Application.DTOs.Responses;
using Maliev.IAMService.Application.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;

namespace Maliev.IAMService.Tests.Unit;

public class AuthControllerLivePermissionCheckTests
{
    private const string LiveCheckCredential = "unit-test-live-check-credential-0123456789";

    [Fact]
    public async Task ResolvePermissionsForTokenIssuance_UsesDedicatedLiveResolver()
    {
        var principalId = Guid.NewGuid();
        var expected = new ResolvePermissionsResponse
        {
            PrincipalId = principalId,
            Permissions = ["project.projects.read"],
            Roles = [],
            FromCache = false
        };
        var resolver = new Mock<IPermissionResolver>();
        resolver
            .Setup(candidate => candidate.ResolvePermissionsForTokenIssuanceAsync(
                It.IsAny<ResolvePermissionsRequest>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(expected);
        var controller = CreateController(
            resolver.Object,
            new Claim("target_principal_id", principalId.ToString("D")));

        var result = await controller.ResolvePermissionsForTokenIssuance(
            new ResolvePermissionsRequest { PrincipalId = principalId.ToString("D") },
            CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.Same(expected, ok.Value);
        resolver.Verify(
            candidate => candidate.ResolvePermissionsForTokenIssuanceAsync(
                It.Is<ResolvePermissionsRequest>(request => request.PrincipalId == principalId.ToString("D")),
                It.IsAny<CancellationToken>()),
            Times.Once);
        resolver.Verify(
            candidate => candidate.ResolvePermissionsAsync(
                It.IsAny<ResolvePermissionsRequest>(),
                It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task CheckPermission_BypassRequestedByEmployee_ReturnsForbiddenWithoutResolving()
    {
        var resolver = CreateResolver();
        var controller = CreateController(
            resolver.Object,
            new Claim("sub", "00000000-0000-0000-0000-000000000002"),
            new Claim("user_type", "employee"));

        var result = await controller.CheckPermission(CreateRequest(bypassCache: true), CancellationToken.None);

        AssertProblem(result, StatusCodes.Status403Forbidden);
        resolver.Verify(
            candidate => candidate.CheckPermissionAsync(It.IsAny<CheckPermissionRequest>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task CheckPermission_StandardCheckByEmployee_ResolvesWithoutLiveCheckAdmission()
    {
        var resolver = CreateResolver();
        var controller = CreateController(
            resolver.Object,
            CreateOptions(),
            new Claim("sub", "00000000-0000-0000-0000-000000000002"),
            new Claim("user_type", "employee"));

        var result = await controller.CheckPermission(CreateRequest(bypassCache: false), CancellationToken.None);

        Assert.IsType<OkObjectResult>(result);
        resolver.Verify(
            candidate => candidate.CheckPermissionAsync(
                It.Is<CheckPermissionRequest>(request => !request.BypassCache),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task CheckPermission_BypassRequestedByAllowlistedServiceWithCanonicalClaimsAndCredential_Resolves()
    {
        var resolver = CreateResolver();
        var controller = CreateController(resolver.Object, CreateOptions(), CreateTrustedServiceClaims());

        var result = await controller.CheckPermission(CreateRequest(bypassCache: true), CancellationToken.None);

        Assert.IsType<OkObjectResult>(result);
        resolver.Verify(
            candidate => candidate.CheckPermissionAsync(
                It.Is<CheckPermissionRequest>(request => request.BypassCache),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task CheckPermission_BypassRequestedWithPerfectClaimsButNoCredential_ReturnsForbidden()
    {
        var resolver = CreateResolver();
        var controller = CreateController(resolver.Object, CreateTrustedServiceClaims());
        controller.Request.Headers.Remove("X-Maliev-IAM-Live-Check-Key");

        var result = await controller.CheckPermission(CreateRequest(bypassCache: true), CancellationToken.None);

        AssertProblem(result, StatusCodes.Status403Forbidden);
        resolver.Verify(
            candidate => candidate.CheckPermissionAsync(It.IsAny<CheckPermissionRequest>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task CheckPermission_BypassRequestedWithPerfectClaimsButWrongCredential_ReturnsForbidden()
    {
        var resolver = CreateResolver();
        var controller = CreateController(resolver.Object, CreateTrustedServiceClaims());
        controller.Request.Headers["X-Maliev-IAM-Live-Check-Key"] = "wrong-credential";

        var result = await controller.CheckPermission(CreateRequest(bypassCache: true), CancellationToken.None);

        AssertProblem(result, StatusCodes.Status403Forbidden);
        resolver.Verify(
            candidate => candidate.CheckPermissionAsync(It.IsAny<CheckPermissionRequest>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task CheckPermission_EmptyCredentialCannotMatchMisconfiguredEmptyCredentialHash()
    {
        var resolver = CreateResolver();
        var controller = CreateController(
            resolver.Object,
            CreateOptions(string.Empty),
            CreateTrustedServiceClaims());
        controller.Request.Headers.Remove("X-Maliev-IAM-Live-Check-Key");

        var result = await controller.CheckPermission(CreateRequest(bypassCache: true), CancellationToken.None);

        AssertProblem(result, StatusCodes.Status403Forbidden);
        resolver.Verify(
            candidate => candidate.CheckPermissionAsync(It.IsAny<CheckPermissionRequest>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Theory]
    [InlineData("OtherService", "system:service:other")]
    [InlineData("IntranetBff", "system:service:other")]
    [InlineData("IntranetBff", "SYSTEM:SERVICE:INTRANETBFF")]
    public async Task CheckPermission_BypassRequestedWithUntrustedServiceIdentity_ReturnsForbidden(
        string serviceName,
        string subject)
    {
        var resolver = CreateResolver();
        var controller = CreateController(
            resolver.Object,
            CreateOptions(),
            CreateTrustedServiceClaims(serviceName, subject));

        var result = await controller.CheckPermission(CreateRequest(bypassCache: true), CancellationToken.None);

        AssertProblem(result, StatusCodes.Status403Forbidden);
        resolver.Verify(
            candidate => candidate.CheckPermissionAsync(It.IsAny<CheckPermissionRequest>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task CheckPermission_AllowlistedServiceNameEndingInService_UsesProductionCanonicalSubject()
    {
        const string serviceName = "PricingService";
        var resolver = CreateResolver();
        var options = CreateOptions();
        options.AllowedServices = [serviceName];
        options.CredentialHashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [serviceName] = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(LiveCheckCredential)))
        };
        var controller = CreateController(
            resolver.Object,
            options,
            CreateTrustedServiceClaims(serviceName, "system:service:pricing"));

        var result = await controller.CheckPermission(CreateRequest(bypassCache: true), CancellationToken.None);

        Assert.IsType<OkObjectResult>(result);
        resolver.Verify(
            candidate => candidate.CheckPermissionAsync(It.IsAny<CheckPermissionRequest>(), It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Theory]
    [InlineData("user_type")]
    [InlineData("role")]
    [InlineData("purpose")]
    [InlineData("service_name")]
    [InlineData("sub")]
    public async Task CheckPermission_BypassRequestedWithMissingRequiredServiceClaim_ReturnsForbidden(string missingClaim)
    {
        var resolver = CreateResolver();
        var claims = CreateTrustedServiceClaims()
            .Where(claim => !string.Equals(claim.Type, missingClaim, StringComparison.Ordinal))
            .ToArray();
        var controller = CreateController(resolver.Object, CreateOptions(), claims);

        var result = await controller.CheckPermission(CreateRequest(bypassCache: true), CancellationToken.None);

        AssertProblem(result, StatusCodes.Status403Forbidden);
        resolver.Verify(
            candidate => candidate.CheckPermissionAsync(It.IsAny<CheckPermissionRequest>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task CheckPermission_LiveCheckRateLimitExceeded_ReturnsProblemWithRetryAfter()
    {
        var resolver = CreateResolver();
        var options = new LivePermissionCheckOptions
        {
            AllowedServices = ["IntranetBff"],
            ServicePermitLimit = 2,
            TargetPermitLimit = 120,
            WindowSeconds = 60,
            SegmentsPerWindow = 4,
            ConcurrencyLimit = 8,
            CredentialHashes = CreateCredentialHashes()
        };
        var controller = CreateController(resolver.Object, options, CreateTrustedServiceClaims());

        Assert.IsType<OkObjectResult>(await controller.CheckPermission(CreateRequest(bypassCache: true), CancellationToken.None));
        Assert.IsType<OkObjectResult>(await controller.CheckPermission(CreateRequest(bypassCache: true), CancellationToken.None));
        var result = await controller.CheckPermission(CreateRequest(bypassCache: true), CancellationToken.None);

        AssertProblem(result, StatusCodes.Status429TooManyRequests);
        Assert.True(controller.Response.Headers.ContainsKey("Retry-After"));
        Assert.True(int.TryParse(controller.Response.Headers.RetryAfter, out var retryAfterSeconds));
        Assert.True(retryAfterSeconds >= 1);
        resolver.Verify(
            candidate => candidate.CheckPermissionAsync(It.IsAny<CheckPermissionRequest>(), It.IsAny<CancellationToken>()),
            Times.Exactly(2));
    }

    [Fact]
    public async Task CheckPermission_TargetPrincipalLimitExceeded_DoesNotThrottleDifferentPrincipal()
    {
        var resolver = CreateResolver();
        var options = new LivePermissionCheckOptions
        {
            AllowedServices = ["IntranetBff"],
            ServicePermitLimit = 300,
            TargetPermitLimit = 120,
            WindowSeconds = 60,
            SegmentsPerWindow = 4,
            ConcurrencyLimit = 8,
            CredentialHashes = CreateCredentialHashes()
        };
        var controller = CreateController(resolver.Object, options, CreateTrustedServiceClaims());
        const string busyPrincipal = "00000000-0000-0000-0000-000000000101";
        const string otherPrincipal = "00000000-0000-0000-0000-000000000102";

        for (var requestNumber = 0; requestNumber < 120; requestNumber++)
        {
            Assert.IsType<OkObjectResult>(await controller.CheckPermission(
                CreateRequest(bypassCache: true, busyPrincipal),
                CancellationToken.None));
        }

        var saturatedTarget = await controller.CheckPermission(
            CreateRequest(bypassCache: true, busyPrincipal),
            CancellationToken.None);
        var otherTarget = await controller.CheckPermission(
            CreateRequest(bypassCache: true, otherPrincipal),
            CancellationToken.None);

        AssertProblem(saturatedTarget, StatusCodes.Status429TooManyRequests);
        Assert.IsType<OkObjectResult>(otherTarget);
        resolver.Verify(
            candidate => candidate.CheckPermissionAsync(It.IsAny<CheckPermissionRequest>(), It.IsAny<CancellationToken>()),
            Times.Exactly(121));
    }

    [Fact]
    public async Task CheckPermission_TargetLimiterCapacityReached_RejectsNewPartitionWithoutResettingExistingBudget()
    {
        var resolver = CreateResolver();
        var options = new LivePermissionCheckOptions
        {
            AllowedServices = ["IntranetBff"],
            ServicePermitLimit = 10,
            TargetPermitLimit = 1,
            WindowSeconds = 60,
            SegmentsPerWindow = 4,
            ConcurrencyLimit = 8,
            TargetLimiterCapacity = 1,
            CredentialHashes = CreateCredentialHashes()
        };
        var controller = CreateController(resolver.Object, options, CreateTrustedServiceClaims());
        const string firstPrincipal = "00000000-0000-0000-0000-000000000201";
        const string secondPrincipal = "00000000-0000-0000-0000-000000000202";

        Assert.IsType<OkObjectResult>(await controller.CheckPermission(
            CreateRequest(bypassCache: true, firstPrincipal),
            CancellationToken.None));
        var newPartition = await controller.CheckPermission(
            CreateRequest(bypassCache: true, secondPrincipal),
            CancellationToken.None);
        var existingPartition = await controller.CheckPermission(
            CreateRequest(bypassCache: true, firstPrincipal),
            CancellationToken.None);

        AssertProblem(newPartition, StatusCodes.Status429TooManyRequests);
        AssertProblem(existingPartition, StatusCodes.Status429TooManyRequests);
        resolver.Verify(
            candidate => candidate.CheckPermissionAsync(It.IsAny<CheckPermissionRequest>(), It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task CheckPermission_RejectedBusyTarget_DoesNotConsumeOtherTargetsServiceBudget()
    {
        var resolver = CreateResolver();
        var options = new LivePermissionCheckOptions
        {
            AllowedServices = ["IntranetBff"],
            ServicePermitLimit = 2,
            TargetPermitLimit = 1,
            WindowSeconds = 60,
            SegmentsPerWindow = 4,
            ConcurrencyLimit = 8,
            CredentialHashes = CreateCredentialHashes()
        };
        var controller = CreateController(resolver.Object, options, CreateTrustedServiceClaims());
        const string busyPrincipal = "00000000-0000-0000-0000-000000000301";
        const string otherPrincipal = "00000000-0000-0000-0000-000000000302";

        Assert.IsType<OkObjectResult>(await controller.CheckPermission(
            CreateRequest(bypassCache: true, busyPrincipal),
            CancellationToken.None));

        for (var attempt = 0; attempt < 3; attempt++)
        {
            var rejected = await controller.CheckPermission(
                CreateRequest(bypassCache: true, busyPrincipal),
                CancellationToken.None);
            AssertProblem(rejected, StatusCodes.Status429TooManyRequests);
        }

        var otherTarget = await controller.CheckPermission(
            CreateRequest(bypassCache: true, otherPrincipal),
            CancellationToken.None);

        Assert.IsType<OkObjectResult>(otherTarget);
        resolver.Verify(
            candidate => candidate.CheckPermissionAsync(It.IsAny<CheckPermissionRequest>(), It.IsAny<CancellationToken>()),
            Times.Exactly(2));
    }

    [Fact]
    public async Task CheckPermission_LiveCheckConcurrencyLimitExceeded_ReturnsProblemWithoutResolvingSecondRequest()
    {
        var enteredResolver = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseResolver = new TaskCompletionSource<CheckPermissionResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        var resolverCalls = 0;
        var resolver = new Mock<IPermissionResolver>();
        resolver
            .Setup(candidate => candidate.CheckPermissionAsync(It.IsAny<CheckPermissionRequest>(), It.IsAny<CancellationToken>()))
            .Returns(() =>
            {
                if (Interlocked.Increment(ref resolverCalls) == 1)
                {
                    enteredResolver.TrySetResult();
                    return releaseResolver.Task;
                }

                return Task.FromResult(CreateResponse());
            });
        var options = new LivePermissionCheckOptions
        {
            AllowedServices = ["IntranetBff"],
            ServicePermitLimit = 2,
            TargetPermitLimit = 120,
            WindowSeconds = 60,
            SegmentsPerWindow = 4,
            ConcurrencyLimit = 1,
            CredentialHashes = CreateCredentialHashes()
        };
        var controller = CreateController(resolver.Object, options, CreateTrustedServiceClaims());

        var firstRequest = controller.CheckPermission(CreateRequest(bypassCache: true), CancellationToken.None);
        await enteredResolver.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var secondResult = await controller.CheckPermission(CreateRequest(bypassCache: true), CancellationToken.None);

        AssertProblem(secondResult, StatusCodes.Status429TooManyRequests);
        resolver.Verify(
            candidate => candidate.CheckPermissionAsync(It.IsAny<CheckPermissionRequest>(), It.IsAny<CancellationToken>()),
            Times.Once);

        releaseResolver.SetResult(CreateResponse());
        Assert.IsType<OkObjectResult>(await firstRequest);

        var thirdResult = await controller.CheckPermission(CreateRequest(bypassCache: true), CancellationToken.None);
        Assert.IsType<OkObjectResult>(thirdResult);
        resolver.Verify(
            candidate => candidate.CheckPermissionAsync(It.IsAny<CheckPermissionRequest>(), It.IsAny<CancellationToken>()),
            Times.Exactly(2));
    }

    [Fact]
    public async Task AcquireAsync_RecordsBoundedLiveCheckMetricTags()
    {
        var counterMeasurements = new List<(string Instrument, long Value, KeyValuePair<string, object?>[] Tags)>();
        var durationMeasurements = new List<(double Value, KeyValuePair<string, object?>[] Tags)>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, activeListener) =>
        {
            if (instrument.Meter.Name == "iam-service" && instrument.Name.StartsWith("iam.live_permission_check", StringComparison.Ordinal))
            {
                activeListener.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
            counterMeasurements.Add((instrument.Name, value, tags.ToArray())));
        listener.SetMeasurementEventCallback<double>((_, value, tags, _) =>
            durationMeasurements.Add((value, tags.ToArray())));
        listener.Start();
        using var guard = new LivePermissionCheckGuard(Options.Create(CreateOptions()));
        var identity = new ClaimsIdentity(CreateTrustedServiceClaims(), "TestBearer", "sub", "role");

        var admission = await guard.AcquireAsync(
            new ClaimsPrincipal(identity),
            "00000000-0000-0000-0000-000000000003",
            LiveCheckCredential);
        admission.Lease?.Dispose();

        Assert.Contains(counterMeasurements, measurement =>
            measurement.Instrument == "iam.live_permission_checks"
            && HasTags(measurement.Tags, "accepted"));
        Assert.Contains(counterMeasurements, measurement =>
            measurement.Instrument == "iam.live_permission_checks.in_flight"
            && measurement.Value == 1
            && HasTags(measurement.Tags, "active"));
        Assert.Contains(counterMeasurements, measurement =>
            measurement.Instrument == "iam.live_permission_checks.in_flight"
            && measurement.Value == -1
            && HasTags(measurement.Tags, "active"));
        Assert.Contains(durationMeasurements, measurement =>
            measurement.Value >= 0
            && HasTags(measurement.Tags, "completed"));
    }

    [Fact]
    public void Constructor_TargetLimiterIdleDurationShorterThanRateWindow_RejectsConfiguration()
    {
        var options = CreateOptions();
        options.WindowSeconds = 120;
        options.TargetLimiterIdleMinutes = 1;

        var exception = Assert.Throws<ArgumentException>(() =>
            new LivePermissionCheckGuard(Options.Create(options)));

        Assert.Contains("idle duration", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("not-base64")]
    [InlineData("c2hvcnQ=")]
    public void Constructor_MissingOrMalformedCredentialVerifier_RejectsConfiguration(string? configuredHash)
    {
        var options = CreateOptions();
        options.CredentialHashes.Clear();
        if (configuredHash is not null)
        {
            options.CredentialHashes["IntranetBff"] = configuredHash;
        }

        var exception = Assert.Throws<ArgumentException>(() =>
            new LivePermissionCheckGuard(Options.Create(options)));

        Assert.Contains("credential verifier", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static Mock<IPermissionResolver> CreateResolver()
    {
        var resolver = new Mock<IPermissionResolver>();
        resolver
            .Setup(candidate => candidate.CheckPermissionAsync(It.IsAny<CheckPermissionRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateResponse());
        return resolver;
    }

    private static AuthController CreateController(IPermissionResolver resolver, params Claim[] claims) =>
        CreateController(resolver, CreateOptions(), claims);

    private static AuthController CreateController(
        IPermissionResolver resolver,
        LivePermissionCheckOptions options,
        params Claim[] claims)
    {
        var controller = new AuthController(
            resolver,
            Mock.Of<ITokenService>(),
            NullLogger<AuthController>.Instance,
            Mock.Of<IServiceScopeFactory>(),
            new LivePermissionCheckGuard(Options.Create(options)));
        var identity = new ClaimsIdentity(claims, "TestBearer", "sub", "role");
        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(identity)
            }
        };
        controller.Request.Headers["X-Maliev-IAM-Live-Check-Key"] = LiveCheckCredential;
        return controller;
    }

    private static CheckPermissionRequest CreateRequest(
        bool bypassCache,
        string principalId = "00000000-0000-0000-0000-000000000003") => new()
        {
            PrincipalId = principalId,
            PermissionId = "employee.reports.view",
            BypassCache = bypassCache
        };

    private static CheckPermissionResponse CreateResponse() => new()
    {
        PrincipalId = Guid.Parse("00000000-0000-0000-0000-000000000003"),
        PermissionId = "employee.reports.view",
        Allowed = true,
        FromCache = false,
        LatencyMs = 1
    };

    private static Claim[] CreateTrustedServiceClaims(
        string serviceName = "IntranetBff",
        string? subject = null) =>
    [
        new Claim("sub", subject ?? "system:service:intranetbff"),
        new Claim("service_name", serviceName),
        new Claim("user_type", "service"),
        new Claim("role", "service-account"),
        new Claim("purpose", "iam-registration")
    ];

    private static void AssertProblem(IActionResult result, int expectedStatusCode)
    {
        var objectResult = Assert.IsType<ObjectResult>(result);
        Assert.Equal(expectedStatusCode, objectResult.StatusCode);
        var problem = Assert.IsType<ProblemDetails>(objectResult.Value);
        Assert.Equal(expectedStatusCode, problem.Status);
        Assert.Contains("application/problem+json", objectResult.ContentTypes);
    }

    private static bool HasTags(KeyValuePair<string, object?>[] tags, string outcome) =>
        tags.Any(tag => tag.Key == "cache_mode" && Equals(tag.Value, "live"))
        && tags.Any(tag => tag.Key == "outcome" && Equals(tag.Value, outcome))
        && tags.Any(tag => tag.Key == "caller_service" && Equals(tag.Value, "IntranetBff"));

    private static LivePermissionCheckOptions CreateOptions(string credential = LiveCheckCredential) => new()
    {
        AllowedServices = ["IntranetBff"],
        CredentialHashes = CreateCredentialHashes(credential)
    };

    private static Dictionary<string, string> CreateCredentialHashes(string credential = LiveCheckCredential) => new(StringComparer.OrdinalIgnoreCase)
    {
        ["IntranetBff"] = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(credential)))
    };

    [Fact]
    public void LivePermissionCheckOptions_NestedCredentialHashConfiguration_BindsCompletely()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["IAM:LivePermissionChecks:AllowedServices:0"] = "IntranetBff",
                ["IAM:LivePermissionChecks:CredentialHashes:IntranetBff"] =
                    CreateCredentialHashes()["IntranetBff"]
            })
            .Build();
        var options = new LivePermissionCheckOptions();

        configuration.GetSection("IAM:LivePermissionChecks").Bind(options);

        Assert.True(options.HasCompleteCredentialCoverage());
    }
}
