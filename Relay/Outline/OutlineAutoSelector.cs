using SerpiumVPN.Relay.Diagnostics;

namespace SerpiumVPN.Relay.Outline;

public sealed class OutlineAutoSelector
{
    public async Task<string> FindAsync(IReadOnlyList<string> keys, Func<string, CancellationToken, Task> probe,
        IProgress<(int Index, int Total)>? progress, CancellationToken token)
    {
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(token);
        budget.CancelAfter(TimeSpan.FromMinutes(2));
        string[] candidates = keys.Distinct(StringComparer.Ordinal).Take(OutlineKeySource.MaximumCandidates).ToArray();
        try
        {
            for (int i = 0; i < candidates.Length; i++)
            {
                budget.Token.ThrowIfCancellationRequested();
                progress?.Report((i + 1, candidates.Length));
                using var attempt = CancellationTokenSource.CreateLinkedTokenSource(budget.Token);
                attempt.CancelAfter(TimeSpan.FromSeconds(15));
                try
                {
                    await probe(candidates[i], attempt.Token);
                    attempt.Token.ThrowIfCancellationRequested();
                    return candidates[i];
                }
                catch (OperationCanceledException) when (!budget.IsCancellationRequested) { }
                catch (ConnectionCheckException error) when (error.Kind is not (ConnectionFailureKind.EngineMissing or ConnectionFailureKind.ProbeUnavailable)) { }
            }
            throw new ConnectionCheckException(ConnectionFailureKind.OutlineNoWorkingKey);
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        { throw new ConnectionCheckException(ConnectionFailureKind.OutlineNoWorkingKey); }
    }
}
