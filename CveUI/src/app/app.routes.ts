import { Routes } from '@angular/router';
import { CapecDetailPage } from './pages/capec-detail.page';
import { CveDetailPage } from './pages/cve-detail.page';
import { CveListPage } from './pages/cve-list.page';
import { SearchPage } from './pages/search.page';
import { VendorsPage } from './pages/vendors.page';
import { VendorProductsPage } from './pages/vendor-products.page';
import { CweDetailPage } from './pages/cwe-detail.page';

export const routes: Routes = [
  { path: '', component: SearchPage, title: 'CveUI — Home' },
  { path: 'cves', component: CveListPage, title: 'CveUI — CVE List' },
  { path: 'cves/:cveId', component: CveDetailPage, title: 'CveUI — CVE' },
  { path: 'cwe/:id', component: CweDetailPage, title: 'CveUI — CWE' },
  { path: 'capec/:id', component: CapecDetailPage, title: 'CveUI — CAPEC' },
  { path: 'vendors', component: VendorsPage, title: 'CveUI — Vendors' },
  { path: 'vendors/:vendor', component: VendorProductsPage, title: 'CveUI — Products' },
  { path: '**', redirectTo: '' },
];
