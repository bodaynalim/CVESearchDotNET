using AutoMapper;
using Cve.Application.Services;
using Cve.DomainModels.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Threading.Tasks;

namespace CVESearch.Controllers
{
    [Route("cve")]
    public class CveController : Controller
    {
        private readonly ICveMongoService _cveMongoService;
        private readonly IMapper _mapper;

        public CveController(ICveMongoService cveMongoService, IMapper mapper)
        {
            _cveMongoService = cveMongoService;
            _mapper = mapper;
        }

        /// <summary>
        /// Search CVEs by vendor and product
        /// </summary>
        /// <param name="vendor">Vulnarable vendor</param>
        /// <param name="product">Vulnarable product</param>
        /// <param name="count">Count of cves</param>
        /// <param name="page">Page</param>
        /// <param name="descending">Sorting by published date ('true' by DESC)</param>
        /// <returns></returns>
        [HttpGet("search/{vendor}/{product}/{count}/{page}/{descending}")]
        public async Task<IActionResult> Search(string vendor, string product, int count, int page, bool descending)
        {
            var cves = await _cveMongoService.GetCveList(vendor, product, count, page, descending);

            return Ok(cves.Select(c => _mapper.Map<CveViewModel>(c)));
        }

        /// <summary>
        /// Get CVE by ID
        /// </summary>
        /// <param name="cveId">CVE ID (ex. CVE-2018-0001)</param>
        /// <returns></returns>
        [HttpGet("{cveId}")]
        public async Task<IActionResult> Get(string cveId)
        {
            var cve = await _cveMongoService.Get(cveId);

            if (cve == null)
                return NotFound($"{cveId} is not found");

            return Ok(_mapper.Map<CveViewModel>(cve));
        }
    }
}
