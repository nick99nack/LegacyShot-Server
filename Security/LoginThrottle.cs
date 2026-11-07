using System.Collections.Concurrent;
using Microsoft.Extensions.Options;

namespace LegacyShot.Server.Security;

// 
// Locks a username or source IP after N failed logins inside a window
// (default: 5 failures in 10 minutes → locked for 15 minutes).
// 
public sealed class LoginThrottle
{
    private sealed class Entry
    {
        public readonly Queue<DateTime> Failures = new();
        public DateTime LockedUntilUtc;
    }

    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly ServerOptions _options;

    public LoginThrottle(IOptions<ServerOptions> options) => _options = options.Value;

    public static string UserKey(string username) => "u:" + username;
    public static string IpKey(string ip) => "ip:" + ip;

    // Seconds remaining on the longest active lock among the keys, or 0 if none is locked.
    public int LockedSeconds(params string[] keys)
    {
        var now = DateTime.UtcNow;
        double longest = 0;
        foreach (var key in keys)
        {
            if (!_entries.TryGetValue(key, out var e))
                continue;
            lock (e)
            {
                if (e.LockedUntilUtc > now)
                    longest = Math.Max(longest, (e.LockedUntilUtc - now).TotalSeconds);
            }
        }
        return (int)Math.Ceiling(longest);
    }

    public void RecordFailure(params string[] keys)
    {
        var now = DateTime.UtcNow;
        var window = TimeSpan.FromMinutes(_options.LockoutWindowMinutes);
        foreach (var key in keys)
        {
            var e = _entries.GetOrAdd(key, _ => new Entry());
            lock (e)
            {
                e.Failures.Enqueue(now);
                while (e.Failures.Count > 0 && now - e.Failures.Peek() > window)
                    e.Failures.Dequeue();
                if (e.Failures.Count >= _options.LockoutFailures)
                {
                    e.LockedUntilUtc = now.AddMinutes(_options.LockoutMinutes);
                    e.Failures.Clear();
                }
            }
        }
    }

    public void RecordSuccess(string key) => _entries.TryRemove(key, out _);

    // Drops entries with no recent failures and no active lock.
    public void Prune()
    {
        var now = DateTime.UtcNow;
        var window = TimeSpan.FromMinutes(_options.LockoutWindowMinutes);
        foreach (var (key, e) in _entries)
        {
            bool stale;
            lock (e)
                stale = e.LockedUntilUtc <= now && (e.Failures.Count == 0 || now - e.Failures.Last() > window);
            if (stale)
                _entries.TryRemove(key, out _);
        }
    }
}
