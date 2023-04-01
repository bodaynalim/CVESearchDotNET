using AutoMapper;
using Cve.Net.Search.Application.Services.Cve;
using Cve.Net.Search.Domain.ViewModels;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
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
        /// <param name="descending">True if order by descending</param>
        /// <param name="byPublished">True if order by published date (else by modified date)</param>
        /// <returns></returns>
        [HttpGet("search/{vendor}/{product}/{count}/{page}/{descending}")]
        [ProducesResponseType(typeof(IEnumerable<CveViewModel>), StatusCodes.Status200OK)]
        public async Task<IActionResult> Search(string vendor, string product, int count, int page, bool descending, 
            bool byPublished)
        {
            var cves = await _cveMongoService.GetCveList(vendor, product, count, page, descending, byPublished);

            return Ok(cves.Select(c => _mapper.Map<CveViewModel>(c)));
        }

        /// <summary>
        /// Get CVE by ID
        /// </summary>
        /// <param name="cveId">CVE ID (ex. CVE-2018-0001)</param>
        /// <returns></returns>
        [HttpGet("{cveId}")]
        [ProducesResponseType(typeof(CveViewModel), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> Get(string cveId)
        {
            var cve = await _cveMongoService.Get(cveId);

            if (cve == null)
                return NotFound($"{cveId} is not found");

            return Ok(_mapper.Map<CveViewModel>(cve));
        }

        /// <summary>
        /// Get last CVE ID by published date for vendor and product
        /// </summary>
        /// <param name="vendor">Vulnarable vendor</param>
        /// <param name="product">Vulnarable product</param>
        /// <returns></returns>
        [HttpGet("last/published/{vendor}/{product}")]
        [ProducesResponseType(typeof(string), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> GetLastPublished(string vendor, string product)
        {
            var cve = await _cveMongoService.GetLastOnePublished(vendor, product);

            if (cve == null)
                return NotFound($"CVE for {vendor} {product} is not found");

            return Ok(cve.CveId);
        }

        /// <summary>
        ///  Get last CVE ID by modified date for vendor and product
        /// </summary>
        /// <param name="vendor">Vulnarable vendor</param>
        /// <param name="product">Vulnarable product</param>
        /// <returns></returns>
        [HttpGet("last/modified/{vendor}/{product}")]
        [ProducesResponseType(typeof(string), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> GetLastModified(string vendor, string product)
        {
            var cve = await _cveMongoService.GetLastOneModified(vendor, product);

            if (cve == null)
                return NotFound($"CVE for {vendor} {product} is not found");

            return Ok(cve.CveId);
        }
    }
}
