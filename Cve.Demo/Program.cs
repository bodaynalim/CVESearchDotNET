using Cve.Infrastructure.Helpers;
using Cve.Infrastructure.Services;
using System.Threading.Tasks;

namespace Cve.Demo
{
    public class Program
    {
        static async Task Main(string[] args)
        {
            //var jsonHelper = new VulnerabilitiesJsonHelper(new CveMongoService(), new CweMongoService(), new CapecMongoService());

            //await jsonHelper.DeserializeAndSaveCveJson(@"C:\Users\BohdanNalyvaiko(Appt\Downloads\nvdcve-1.1-2022.json");
            //await jsonHelper.DeserializeAndSaveCweXml(@"C:\Users\BohdanNalyvaiko(Appt\Downloads\cwec_v4.4.xml");
            //await jsonHelper.DeserializeAndSaveCapecXml(@"C:\Users\BohdanNalyvaiko(Appt\Downloads\capec_v3.7.xml");
        }
    }
}