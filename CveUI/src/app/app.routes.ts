import { Routes } from '@angular/router';
import { CapecDetailPage } from './pages/capec-detail.page';
import { CveDetailPage } from './pages/cve-detail.page';
import { CveListPage } from './pages/cve-list.page';
import { VendorsPage } from './pages/vendors.page';
import { VendorProductsPage } from './pages/vendor-products.page';
import { CweDetailPage } from './pages/cwe-detail.page';
import { CweListPage } from './pages/cwe-list.page';

export const routes: Routes = [
  // The browse-all CVE list is the default view; old home URLs redirect to it.
  { path: '', redirectTo: 'cves', pathMatch: 'full' },
  { path: 'cves', component: CveListPage, title: 'CveUI — CVEs' },
  { path: 'cves/:cveId', component: CveDetailPage, title: 'CveUI — CVE' },
  { path: 'cwe', component: CweListPage, title: 'CveUI — Weaknesses' },
  { path: 'cwe/:id', component: CweDetailPage, title: 'CveUI — CWE' },
  { path: 'capec/:id', component: CapecDetailPage, title: 'CveUI — CAPEC' },
  { path: 'vendors', component: VendorsPage, title: 'CveUI — Vendors' },
  { path: 'vendors/:vendor', component: VendorProductsPage, title: 'CveUI — Products' },
  { path: '**', redirectTo: '' },
];
