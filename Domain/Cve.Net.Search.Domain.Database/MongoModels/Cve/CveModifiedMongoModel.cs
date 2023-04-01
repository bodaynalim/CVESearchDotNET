using System;

namespace Cve.Net.Search.Domain.Database.MongoModels.Cve
{
    /// <summary>
    /// CVE modified mongo model
    /// </summary>
    public class CveModifiedMongoModel : BaseMongoModel
    {
        public string CveId { get; set; }

        public DateTime Modified { get; set; }

        public Change[] Changes { get; set; }
    }

    public class Change
    {
        public string PropertyName { get; set; }

        public string PropertyDescription { get; set; }

        public object OldValue { get; set; }

        public object NewValue { get; set; }
    }
}
