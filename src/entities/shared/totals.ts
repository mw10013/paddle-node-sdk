/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */

import { type ITotals } from '../../types';

export class Totals {
  public readonly subtotal: string;
  public readonly discount: string;
  public readonly tax: string;
  public readonly total: string;

  constructor(totals: ITotals) {
    this.subtotal = totals.subtotal;
    this.discount = totals.discount;
    this.tax = totals.tax;
    this.total = totals.total;
  }
}
