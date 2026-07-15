using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.Extensions.Options;

namespace Maliev.IAMService.Api.Authorization;

/// <summary>
/// Describes the admission decision for an authoritative permission check.
/// </summary>
public enum LivePermissionCheckDecision
{
    /// <summary>The caller is trusted and capacity is available.</summary>
    Acquired,

    /// <summary>The caller does not have the required service identity.</summary>
    Forbidden,

    /// <summary>The caller is trusted but live-check capacity is exhausted.</summary>
    RateLimited
}

/// <summary>
/// Validates service identities before authoritative permission checks are executed.
/// </summary>
public sealed class LivePermissionCheckGuard : IDisposable
{
    private readonly IReadOnlyDictionary<string, string> _allowedServices;
    private readonly IReadOnlyDictionary<string, byte[]> _credentialHashes;
    private readonly IReadOnlyDictionary<string, SlidingWindowRateLimiter> _serviceLimiters;
    private readonly Dictionary<string, TargetLimiterEntry> _targetLimiters = new(StringComparer.Ordinal);
    private readonly object _targetLimiterLock = new();
    private readonly ConcurrencyLimiter _concurrencyLimiter;
    private readonly LivePermissionCheckOptions _options;
    private readonly Meter _meter;
    private readonly Counter<long> _requestCounter;
    private readonly UpDownCounter<long> _inFlightCounter;
    private readonly Histogram<double> _durationHistogram;
    private long _lastTargetPruneTicks = DateTime.UtcNow.Ticks;

    /// <summary>
    /// Initializes a new instance of the <see cref="LivePermissionCheckGuard"/> class.
    /// </summary>
    /// <param name="options">Live permission-check configuration.</param>
    public LivePermissionCheckGuard(IOptions<LivePermissionCheckOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options.Value;
        ValidateOptions(_options);
        _allowedServices = _options.AllowedServices
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToDictionary(service => service, service => service, StringComparer.OrdinalIgnoreCase);
        _credentialHashes = ParseCredentialHashes(_options.CredentialHashes);
        _serviceLimiters = _allowedServices.Values.ToDictionary(
            service => service,
            _ => CreateServiceLimiter(),
            StringComparer.OrdinalIgnoreCase);
        _concurrencyLimiter = new ConcurrencyLimiter(new ConcurrencyLimiterOptions
        {
            PermitLimit = _options.ConcurrencyLimit,
            QueueLimit = 0,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst
        });
        _meter = new Meter("iam-service");
        _requestCounter = _meter.CreateCounter<long>(
            "iam.live_permission_checks",
            description: "Authoritative permission-check admission decisions.");
        _inFlightCounter = _meter.CreateUpDownCounter<long>(
            "iam.live_permission_checks.in_flight",
            description: "Authoritative permission checks currently executing in this pod.");
        _durationHistogram = _meter.CreateHistogram<double>(
            "iam.live_permission_check.duration",
            unit: "ms",
            description: "Authoritative permission-check execution duration.");
    }

    /// <summary>
    /// Validates the authenticated service identity and attempts to reserve live-check capacity.
    /// </summary>
    /// <param name="caller">Authenticated caller claims.</param>
    /// <param name="targetPrincipalId">Principal whose permission is being checked.</param>
    /// <param name="credential">Per-service live-check credential supplied separately from the fleet JWT.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The admission decision, optional capacity lease, normalized caller service, and retry delay.</returns>
    public async ValueTask<(LivePermissionCheckDecision Decision, IDisposable? Lease, string CallerService, TimeSpan? RetryAfter)> AcquireAsync(
        ClaimsPrincipal caller,
        string targetPrincipalId,
        string? credential,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetPrincipalId);
        cancellationToken.ThrowIfCancellationRequested();

        var serviceName = caller.FindFirst("service_name")?.Value;
        var expectedSubject = string.IsNullOrWhiteSpace(serviceName)
            ? null
            : $"system:service:{serviceName.ToLowerInvariant().Replace("service", string.Empty, StringComparison.Ordinal)}";
        string? canonicalServiceName = null;
        var isAllowlisted = !string.IsNullOrWhiteSpace(serviceName)
            && _allowedServices.TryGetValue(serviceName, out canonicalServiceName);
        var isTrusted = caller.Identity?.IsAuthenticated == true
            && string.Equals(caller.FindFirst("user_type")?.Value, "service", StringComparison.Ordinal)
            && caller.IsInRole("service-account")
            && string.Equals(caller.FindFirst("purpose")?.Value, "iam-registration", StringComparison.Ordinal)
            && isAllowlisted
            && string.Equals(caller.FindFirst("sub")?.Value, expectedSubject, StringComparison.Ordinal)
            && HasValidCredential(canonicalServiceName, credential);

        if (!isTrusted)
        {
            Record("forbidden", "untrusted");
            return (LivePermissionCheckDecision.Forbidden, null, "untrusted", null);
        }

        var concurrencyLease = await _concurrencyLimiter.AcquireAsync(1, cancellationToken);
        if (!concurrencyLease.IsAcquired)
        {
            concurrencyLease.Dispose();
            Record("concurrency_limited", canonicalServiceName!);
            return (LivePermissionCheckDecision.RateLimited, null, canonicalServiceName!, TimeSpan.FromSeconds(1));
        }

        var targetAdmission = AcquireTargetRate(canonicalServiceName!, targetPrincipalId);
        if (!targetAdmission.Acquired)
        {
            concurrencyLease.Dispose();
            Record("target_rate_limited", canonicalServiceName!);
            return (
                LivePermissionCheckDecision.RateLimited,
                null,
                canonicalServiceName!,
                targetAdmission.RetryAfter ?? TimeSpan.FromSeconds(1));
        }

        var serviceRateLease = await _serviceLimiters[canonicalServiceName!].AcquireAsync(1, cancellationToken);
        if (!serviceRateLease.IsAcquired)
        {
            var retryAfter = GetRetryAfter(serviceRateLease);
            serviceRateLease.Dispose();
            concurrencyLease.Dispose();
            Record("service_rate_limited", canonicalServiceName!);
            return (LivePermissionCheckDecision.RateLimited, null, canonicalServiceName!, retryAfter);
        }

        serviceRateLease.Dispose();

        Record("accepted", canonicalServiceName!);
        RecordInFlight(1, canonicalServiceName!);
        var startedAt = Stopwatch.GetTimestamp();
        return (
            LivePermissionCheckDecision.Acquired,
            new CompositeLease(
                concurrencyLease,
                () => RecordCompletion(startedAt, canonicalServiceName!)),
            canonicalServiceName!,
            null);
    }

    /// <summary>Releases limiter and metrics resources owned by this singleton.</summary>
    public void Dispose()
    {
        foreach (var limiter in _serviceLimiters.Values)
        {
            limiter.Dispose();
        }

        lock (_targetLimiterLock)
        {
            foreach (var entry in _targetLimiters.Values)
            {
                entry.Limiter.Dispose();
            }

            _targetLimiters.Clear();
        }

        _concurrencyLimiter.Dispose();
        _meter.Dispose();
    }

    private SlidingWindowRateLimiter CreateServiceLimiter() => new(new SlidingWindowRateLimiterOptions
    {
        PermitLimit = _options.ServicePermitLimit,
        Window = TimeSpan.FromSeconds(_options.WindowSeconds),
        SegmentsPerWindow = _options.SegmentsPerWindow,
        QueueLimit = 0,
        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
        AutoReplenishment = true
    });

    private (bool Acquired, TimeSpan? RetryAfter) AcquireTargetRate(
        string canonicalServiceName,
        string targetPrincipalId)
    {
        var partitionValue = $"{canonicalServiceName.Length}:{canonicalServiceName}{targetPrincipalId}";
        var targetKey = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(partitionValue)));
        var nowTicks = DateTime.UtcNow.Ticks;

        lock (_targetLimiterLock)
        {
            PruneTargetLimiters(nowTicks);
            if (_targetLimiters.TryGetValue(targetKey, out var existing))
            {
                existing.LastAccessTicks = nowTicks;
                using var existingLease = existing.Limiter.AttemptAcquire(1);
                return existingLease.IsAcquired
                    ? (true, null)
                    : (false, GetRetryAfter(existingLease));
            }

            if (_targetLimiters.Count >= _options.TargetLimiterCapacity)
            {
                return (false, TimeSpan.FromSeconds(1));
            }

            var limiter = new SlidingWindowRateLimiter(new SlidingWindowRateLimiterOptions
            {
                PermitLimit = _options.TargetPermitLimit,
                Window = TimeSpan.FromSeconds(_options.WindowSeconds),
                SegmentsPerWindow = _options.SegmentsPerWindow,
                QueueLimit = 0,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                AutoReplenishment = true
            });
            _targetLimiters[targetKey] = new TargetLimiterEntry(limiter, nowTicks);
            using var newLease = limiter.AttemptAcquire(1);
            return newLease.IsAcquired
                ? (true, null)
                : (false, GetRetryAfter(newLease));
        }
    }

    private void PruneTargetLimiters(long nowTicks)
    {
        var pruneIntervalTicks = TimeSpan.FromMinutes(1).Ticks;
        if (_targetLimiters.Count < _options.TargetLimiterCapacity
            && nowTicks - _lastTargetPruneTicks < pruneIntervalTicks)
        {
            return;
        }

        _lastTargetPruneTicks = nowTicks;
        var idleCutoff = nowTicks - TimeSpan.FromMinutes(_options.TargetLimiterIdleMinutes).Ticks;
        foreach (var staleKey in _targetLimiters
                     .Where(pair => pair.Value.LastAccessTicks <= idleCutoff)
                     .Select(pair => pair.Key)
                     .ToArray())
        {
            if (_targetLimiters.Remove(staleKey, out var stale))
            {
                stale.Limiter.Dispose();
            }
        }
    }

    private bool HasValidCredential(string? canonicalServiceName, string? credential)
    {
        if (canonicalServiceName is null || !_credentialHashes.TryGetValue(canonicalServiceName, out var expectedHash))
        {
            return false;
        }

        if (credential is not { Length: >= 32 and <= 512 } || string.IsNullOrWhiteSpace(credential))
        {
            return false;
        }

        var credentialBytes = Encoding.UTF8.GetBytes(credential);
        var actualHash = SHA256.HashData(credentialBytes);
        return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
    }

    private static IReadOnlyDictionary<string, byte[]> ParseCredentialHashes(IReadOnlyDictionary<string, string> configuredHashes)
    {
        var parsed = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var (serviceName, configuredHash) in configuredHashes)
        {
            byte[] hash;
            try
            {
                hash = Convert.FromBase64String(configuredHash);
            }
            catch (FormatException ex)
            {
                throw new ArgumentException($"Live-check credential hash for service '{serviceName}' is not valid Base64.", nameof(configuredHashes), ex);
            }

            if (hash.Length != SHA256.HashSizeInBytes)
            {
                throw new ArgumentException($"Live-check credential hash for service '{serviceName}' must be a SHA-256 hash.", nameof(configuredHashes));
            }

            parsed[serviceName] = hash;
        }

        return parsed;
    }

    private static TimeSpan GetRetryAfter(RateLimitLease lease) =>
        lease.TryGetMetadata(MetadataName.RetryAfter, out var delay)
            ? delay
            : TimeSpan.FromSeconds(1);

    private void Record(string outcome, string callerService)
    {
        _requestCounter.Add(
            1,
            new KeyValuePair<string, object?>("cache_mode", "live"),
            new KeyValuePair<string, object?>("outcome", outcome),
            new KeyValuePair<string, object?>("caller_service", callerService));
    }

    private void RecordInFlight(long delta, string callerService)
    {
        _inFlightCounter.Add(
            delta,
            new KeyValuePair<string, object?>("cache_mode", "live"),
            new KeyValuePair<string, object?>("outcome", "active"),
            new KeyValuePair<string, object?>("caller_service", callerService));
    }

    private void RecordCompletion(long startedAt, string callerService)
    {
        RecordInFlight(-1, callerService);
        _durationHistogram.Record(
            Stopwatch.GetElapsedTime(startedAt).TotalMilliseconds,
            new KeyValuePair<string, object?>("cache_mode", "live"),
            new KeyValuePair<string, object?>("outcome", "completed"),
            new KeyValuePair<string, object?>("caller_service", callerService));
    }

    private static void ValidateOptions(LivePermissionCheckOptions options)
    {
        if (!options.HasCompleteCredentialCoverage())
        {
            throw new ArgumentException(
                "Every distinct live permission-check service must have a Base64 SHA-256 credential verifier.",
                nameof(options));
        }

        if (options.ServicePermitLimit <= 0
            || options.TargetPermitLimit <= 0
            || options.WindowSeconds <= 0
            || options.SegmentsPerWindow <= 0
            || options.ConcurrencyLimit <= 0
            || options.TargetLimiterCapacity <= 0
            || options.TargetLimiterIdleMinutes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "Live permission-check limits must be positive.");
        }

        if ((long)options.TargetLimiterIdleMinutes * 60 < options.WindowSeconds)
        {
            throw new ArgumentException(
                "Target limiter idle duration must be at least as long as the sliding rate window.",
                nameof(options));
        }
    }

    private sealed class CompositeLease(
        IDisposable concurrencyLease,
        Action onDispose) : IDisposable
    {
        private IDisposable? _concurrencyLease = concurrencyLease;
        private Action? _onDispose = onDispose;

        public void Dispose()
        {
            Interlocked.Exchange(ref _concurrencyLease, null)?.Dispose();
            Interlocked.Exchange(ref _onDispose, null)?.Invoke();
        }
    }

    private sealed class TargetLimiterEntry(SlidingWindowRateLimiter limiter, long lastAccessTicks)
    {
        public SlidingWindowRateLimiter Limiter { get; } = limiter;

        public long LastAccessTicks { get; set; } = lastAccessTicks;
    }
}
