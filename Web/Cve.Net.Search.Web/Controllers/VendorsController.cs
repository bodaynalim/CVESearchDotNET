using AutoMapper;
using Cve.Application.Services;
using Cve.Net.Search.Domain.ViewModels;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace CVESearch.Controllers
{
    [Route("vendors")]
    public class VendorsController : Controller
    {
        private readonly IVendorMongoService _vendorMongoService;
        private readonly IMapper _mapper;

        public VendorsController(IMapper mapper, IVendorMongoService vendorMongoService)
        {
            _mapper = mapper;
            _vendorMongoService = vendorMongoService;
        }

        /// <summary>
        /// Get all vendors
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [ProducesResponseType(typeof(IEnumerable<string>), StatusCodes.Status200OK)]
        public IActionResult GetAllVendors()
        {
            return Ok(_vendorMongoService.GetAllVendors());
        }

        /// <summary>
        /// Get products by vendor name
        /// </summary>
        /// <param name="vendor">Vendor name</param>
        /// <returns></returns>
        [HttpGet("{vendor}")]
        [ProducesResponseType(typeof(VendorProductsViewModel), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> GetProductsByVendor(string vendor)
        {
            var vendorModel = await _vendorMongoService.Get(vendor);

            if (vendorModel == null)
                return NotFound($"{vendor} is not found");

            return Ok(_mapper.Map<VendorProductsViewModel>(vendorModel));
        }
    }
}
