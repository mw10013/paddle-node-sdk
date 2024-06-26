/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */

import { type CurrencyCode, type AvailablePaymentMethod } from '../../enums';
import { type IPricingPreviewResponse } from '../../types';
import { AddressPreview } from '../transaction';
import { PricingPreviewDetails } from './pricing-preview-details';

export class PricingPreview {
  public readonly customerId: string | null;
  public readonly addressId: string | null;
  public readonly businessId: string | null;
  public readonly currencyCode: CurrencyCode;
  public readonly discountId: string | null;
  public readonly address: AddressPreview | null;
  public readonly customerIpAddress: string | null;
  public readonly details: PricingPreviewDetails;
  public readonly availablePaymentMethods: AvailablePaymentMethod[];

  constructor(pricePreview: IPricingPreviewResponse) {
    this.customerId = pricePreview.customer_id ?? null;
    this.addressId = pricePreview.address_id ?? null;
    this.businessId = pricePreview.business_id ?? null;
    this.currencyCode = pricePreview.currency_code;
    this.discountId = pricePreview.discount_id ?? null;
    this.address = pricePreview.address ? new AddressPreview(pricePreview.address) : null;
    this.customerIpAddress = pricePreview.customer_ip_address ?? null;
    this.details = new PricingPreviewDetails(pricePreview.details);
    this.availablePaymentMethods = pricePreview.available_payment_methods ?? [];
  }
}
