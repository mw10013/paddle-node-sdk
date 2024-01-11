/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */
import { AdjustmentItemTotals, AdjustmentProration } from '../adjustment';
import { type AdjustmentType } from '../../enums';
import { type IAdjustmentItemResponse } from '../../types';

export class NextTransactionAdjustmentItem {
  public readonly itemId: string;
  public readonly type: AdjustmentType;
  public readonly amount: string | null;
  public readonly proration: AdjustmentProration | null;
  public readonly totals: AdjustmentItemTotals | null;

  constructor(adjustmentItem: IAdjustmentItemResponse) {
    this.itemId = adjustmentItem.item_id;
    this.type = adjustmentItem.type;
    this.amount = adjustmentItem.amount ? adjustmentItem.amount : null;
    this.proration = adjustmentItem.proration ? new AdjustmentProration(adjustmentItem.proration) : null;
    this.totals = adjustmentItem.totals ? new AdjustmentItemTotals(adjustmentItem.totals) : null;
  }
}