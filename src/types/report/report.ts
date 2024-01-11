/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */

import { type IReportFilters } from '../index';
import { type ReportType, type ReportStatus } from '../../enums';

export interface IReportResponse {
  id: string;
  status: ReportStatus;
  rows?: number | null;
  type: ReportType;
  filters: IReportFilters[];
  expires_at?: string | null;
  created_at: string;
}