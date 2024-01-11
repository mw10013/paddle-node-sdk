/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */

import { Price } from '../price';
import { Totals } from '../shared';
import { Product } from '../product';
import { PricingPreviewDiscounts } from './pricing-preview-discounts';
import { type IPricingPreviewLineItemResponse } from '../../types';

export class PricingPreviewLineItem {
  public readonly price: Price;
  public readonly quantity: number;
  public readonly taxRate: string;
  public readonly unitTotals: Totals;
  public readonly formattedUnitTotals: Totals;
  public readonly totals: Totals;
  public readonly formattedTotals: Totals;
  public readonly product: Product;
  public readonly discounts: PricingPreviewDiscounts[];

  constructor(lineItem: IPricingPreviewLineItemResponse) {
    this.price = new Price(lineItem.price);
    this.quantity = lineItem.quantity;
    this.taxRate = lineItem.tax_rate;
    this.unitTotals = new Totals(lineItem.unit_totals);
    this.formattedUnitTotals = new Totals(lineItem.formatted_unit_totals);
    this.totals = new Totals(lineItem.totals);
    this.formattedTotals = new Totals(lineItem.formatted_totals);
    this.product = new Product(lineItem.product);
    this.discounts = lineItem.discounts.map((discount) => new PricingPreviewDiscounts(discount));
  }
}
