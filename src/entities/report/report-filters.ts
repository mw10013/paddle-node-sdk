/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */

import { type IReportFilters } from '../../types';
import { type ReportFilterName, type ReportFilterOperator } from '../../enums';

export class ReportFilters {
  public readonly name: ReportFilterName;
  public readonly operator: null | ReportFilterOperator;
  public readonly value: string[] | string;

  constructor(reportFiltersResponse: IReportFilters) {
    this.name = reportFiltersResponse.name;
    this.operator = reportFiltersResponse.operator ?? null;
    this.value = reportFiltersResponse.value;
  }
}
