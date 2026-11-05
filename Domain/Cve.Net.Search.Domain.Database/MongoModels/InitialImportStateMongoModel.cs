namespace Cve.Net.Search.Domain.Database.MongoModels;

public class InitialImportStateMongoModel : BaseMongoModel
{
    /// <summary>
    /// Name of the initial import step, e.g. "cwes", "capecs", "cves-2024".
    /// </summary>
    public string Step { get; set; }

    /// <summary>
    /// UTC date when the step has been completed successfully.
    /// </summary>
    public DateTime CompletedAt { get; set; }
}
