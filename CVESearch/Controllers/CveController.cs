using Cve.Application.Services;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace CVESearch.Controllers
{
    [Route("cve")]
    public class CveController : Controller
    {
        private readonly ICveMongoService _cveMongoService;

        public CveController(ICveMongoService cveMongoService)
        {
            _cveMongoService = cveMongoService;
        }

        [HttpGet("search")]
        public async Task<IActionResult> Search(string vendor, string product, int count, int page, bool descending)
        {
            return Ok(await _cveMongoService.GetCveList(vendor, product, count, page, descending));
        }
    }
}
