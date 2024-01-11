/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */

import {
  type ICustomData,
  type IBillingDetailsResponse,
  type ITransactionsTimePeriodResponse,
  type ITransactionItemResponse,
  type ITransactionDetailsResponse,
  type ITransactionPaymentAttemptResponse,
  type ITransactionCheckout,
  type IAddressResponse,
  type ITransactionAdjustmentResponse,
  type IAdjustmentTotalsResponse,
  type IBusinessResponse,
  type ICustomerResponse,
  type IDiscountResponse,
} from '../index';
import { type TransactionStatus, type CurrencyCode, type TransactionOrigin, type CollectionMode } from '../../enums';

export interface ITransactionResponse {
  id: string;
  status: TransactionStatus;
  customer_id?: string | null;
  address_id?: string | null;
  business_id?: string | null;
  custom_data?: ICustomData | null;
  currency_code: CurrencyCode;
  origin: TransactionOrigin;
  subscription_id?: string | null;
  invoice_id?: string | null;
  invoice_number?: string | null;
  collection_mode: CollectionMode;
  discount_id?: string | null;
  billing_details?: IBillingDetailsResponse | null;
  billing_period?: ITransactionsTimePeriodResponse | null;
  items: ITransactionItemResponse[];
  details?: ITransactionDetailsResponse | null;
  payments: ITransactionPaymentAttemptResponse[];
  checkout?: ITransactionCheckout | null;
  created_at: string;
  updated_at: string;
  billed_at?: string | null;
  address?: IAddressResponse | null;
  adjustments?: ITransactionAdjustmentResponse[] | null;
  adjustments_totals?: IAdjustmentTotalsResponse | null;
  business?: IBusinessResponse | null;
  customer?: ICustomerResponse | null;
  discount?: IDiscountResponse | null;
}
