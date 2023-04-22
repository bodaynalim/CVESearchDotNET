using Cve.Infrastructure.Extensions;
using Cve.Infrastructure.Services;
using Cve.Net.Search.Application.Services.Cve;
using Cve.Net.Search.Domain.Database.CveXmlJsonModels;
using Cve.Net.Search.Domain.Database.Extensions;
using Cve.Net.Search.Domain.Database.MongoModels.Cve;
using MongoDB.Driver;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Cve.Net.Search.Infrastructure.Services.Cve
{
    public class CveModifiedMongoService : BaseMongoService<CveModifiedMongoModel>, ICveModifiedMongoService
    {
        public CveModifiedMongoService(IMongoDatabase db) : base(db, "CvesModified")
        {
            Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveModifiedMongoModel>(Builders<CveModifiedMongoModel>
                .IndexKeys
                .Ascending(c => c.CveId)));

           Collection.Indexes.CreateOneAsync(new CreateIndexModel<CveModifiedMongoModel>(Builders<CveModifiedMongoModel>
               .IndexKeys
               .Descending(c => c.Modified)));
        }

        public override async Task<CveModifiedMongoModel> CreateOrUpdateExisting(CveModifiedMongoModel item)
        {
            var any = await Collection.Find(s => s.CveId == item.CveId).FirstOrDefaultAsync();

            if (any == null)
                return await CreateNewItem(item);
            else
            {
                item.Id = any.Id;

                var result = await Collection.ReplaceOneAsync(e => e.CveId == item.CveId, item);

                return result.IsAcknowledged && result.MatchedCount > 0 ? item : any;
            }
        }

        public override async Task<CveModifiedMongoModel> CreateNewItemIfNotExist(CveModifiedMongoModel item)
        {
            var any = await Collection.Find(s => s.CveId == item.CveId).FirstOrDefaultAsync();

            if (any != null)
                return any;

            await Collection.InsertOneAsync(item);

            return item;
        }

        public override async Task<CveModifiedMongoModel> Get(string id)
        {
            return await Collection.Find(s => s.CveId == id).FirstOrDefaultAsync();
        }

        public async Task LogChanges(CveMongoModel old, CveMongoModel newItem)
        {
            var changes = GetChanges(old, newItem);

            if (changes.Any())
                await CreateNewItem(new CveModifiedMongoModel
                {
                    Changes= changes.ToArray(),
                    CveId = old.CveId,
                    Modified = newItem.Modified
                });
        }

        private static IEnumerable<Change> GetChanges(CveMongoModel old, CveMongoModel changedCve)
        {
            var changes = new List<Change>();

            if (old.Assigner != changedCve.Assigner)
                changes.Add(GetChange(old.Assigner, changedCve.Assigner, nameof(CveMongoModel.Assigner)));

            if (old.Summary != changedCve.Summary)
                changes.Add(GetChange(old.Summary, changedCve.Summary, nameof(CveMongoModel.Summary)));

            if (old.Modified != changedCve.Modified)
                changes.Add(GetChange(old.Modified.ToString(), changedCve.Modified.ToString(), nameof(CveMongoModel.Modified)));

            if (!ObjectExtensions.ObjectsAreEqual(old.Cvss2, changedCve.Cvss2))
                changes.Add(GetChange(old.Cvss2.ToString(), changedCve.Cvss2.ToString(), nameof(CveMongoModel.Cvss2)));

            if (!ObjectExtensions.ObjectsAreEqual(old.Cvss3, changedCve.Cvss3))
                changes.Add(GetChange(old.Cvss3.ToString(), changedCve.Cvss3.ToString(), nameof(CveMongoModel.Cvss3)));

            if (!ObjectExtensions.ObjectsAreEqual(old.References, changedCve.References))
                changes.Add(GetChange(old.References.Select(s => s.ToString()).JoinToString(", \n"),
                    changedCve.References.Select(s => s.ToString()).JoinToString(", \n"), nameof(CveMongoModel.References)));

            if (!ObjectExtensions.ObjectsAreEqual(old.VulnerableConfigurations, changedCve.VulnerableConfigurations))
                changes.Add(GetChange(old.VulnerableConfigurations.Select(s => s.ToString()).JoinToString(", \n"),
                    changedCve.VulnerableConfigurations.Select(s => s.ToString()).JoinToString(", \n"), nameof(CveMongoModel.VulnerableConfigurations)));

            if (!ObjectExtensions.ObjectsAreEqual(old.Cwes, changedCve.Cwes))
                changes.Add(GetChange(old.Cwes.Select(s => s.ToString()).JoinToString(", \n"),
                    changedCve.Cwes.Select(s => s.ToString()).JoinToString(", \n"), nameof(CveMongoModel.Cwes)));

            return changes;
        }

        private static Change GetChange(string oldValue, string newValue, string fieldName)
        {
            return new Change
            {
                OldValue = oldValue,
                NewValue = newValue,
                PropertyDescription = typeof(CveMongoModel).GetFieldDescription(fieldName),
                PropertyName = fieldName
            };
        }
    }
}
