/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */

import { type ISubscriptionPriceResponse } from '../../types';
import { TimePeriod, Money } from '../index';
import { type TaxMode } from '../../enums';

export class SubscriptionPrice {
  public readonly id: string;
  public readonly description: string;
  public readonly productId: string;
  public readonly billingCycle: TimePeriod | null;
  public readonly trialPeriod: TimePeriod | null;
  public readonly taxMode: TaxMode;
  public readonly unitPrice: Money;

  constructor(subscriptionPrice: ISubscriptionPriceResponse) {
    this.id = subscriptionPrice.id;
    this.description = subscriptionPrice.description;
    this.productId = subscriptionPrice.product_id;
    this.billingCycle = subscriptionPrice.billing_cycle ? new TimePeriod(subscriptionPrice.billing_cycle) : null;
    this.trialPeriod = subscriptionPrice.trial_period ? new TimePeriod(subscriptionPrice.trial_period) : null;
    this.taxMode = subscriptionPrice.tax_mode;
    this.unitPrice = new Money(subscriptionPrice.unit_price);
  }
}