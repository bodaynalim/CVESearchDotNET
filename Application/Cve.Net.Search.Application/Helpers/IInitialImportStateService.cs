using Cve.Application.Services;

namespace Cve.Application.Helpers;

/// <summary>
/// Persistent markers for the initial database population:
/// tracks which import steps are already completed, so a retried or
/// restarted initial import resumes instead of failing/partially re-importing.
/// </summary>
public interface IInitialImportStateService : IIndexInitializer
{
    /// <summary>
    /// Returns true when the given initial-import step has been marked as completed previously.
    /// </summary>
    Task<bool> IsStepCompletedAsync(string step, CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks the given initial-import step as completed.
    /// </summary>
    Task MarkStepCompletedAsync(string step, CancellationToken cancellationToken = default);
}
