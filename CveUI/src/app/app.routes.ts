import { Routes } from '@angular/router';
import { VendorsPage } from './pages/vendors.page';
import { VendorProductsPage } from './pages/vendor-products.page';

export const routes: Routes = [
  { path: '', redirectTo: 'vendors', pathMatch: 'full' },
  // Ticket #1 demo route: the vendor → product drill-down lands here in the next ticket.
  { path: 'vendors', component: VendorsPage, title: 'CveUI — Vendors' },
  { path: 'vendors/:vendor', component: VendorProductsPage, title: 'CveUI — Products' },
  { path: '**', redirectTo: 'vendors' },
];
