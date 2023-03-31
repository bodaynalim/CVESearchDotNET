using AutoMapper;
using Cve.Application.Services;
using Cve.DomainModels.ViewModels;
using Microsoft.AspNetCore.Mvc;
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
        public async Task<IActionResult> GetProductsByVendor(string vendor)
        {
            var vendorModel = await _vendorMongoService.Get(vendor);
            return Ok(_mapper.Map<VendorProductsViewModel>(vendorModel));
        }
    }
}
