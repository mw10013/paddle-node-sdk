/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */

import { type ITransactionPayoutTotalsAdjustedResponse } from '../../types';
import { ChargebackFee } from '../index';
import { type PayoutCurrencyCode } from '../../enums';

export class TransactionPayoutTotalsAdjusted {
  public readonly subtotal: string;
  public readonly tax: string;
  public readonly total: string;
  public readonly fee: string;
  public readonly chargebackFee: ChargebackFee | null;
  public readonly earnings: string;
  public readonly currencyCode: PayoutCurrencyCode;

  constructor(transactionPayoutTotalsAdjusted: ITransactionPayoutTotalsAdjustedResponse) {
    this.subtotal = transactionPayoutTotalsAdjusted.subtotal;
    this.tax = transactionPayoutTotalsAdjusted.tax;
    this.total = transactionPayoutTotalsAdjusted.total;
    this.fee = transactionPayoutTotalsAdjusted.fee;
    this.chargebackFee = transactionPayoutTotalsAdjusted.chargeback_fee
      ? new ChargebackFee(transactionPayoutTotalsAdjusted.chargeback_fee)
      : null;
    this.earnings = transactionPayoutTotalsAdjusted.earnings;
    this.currencyCode = transactionPayoutTotalsAdjusted.currency_code;
  }
}