/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */
import { type DiscountStatus } from '../../../enums';

export interface ListDiscountQueryParameters {
  after?: string;
  code?: string[];
  id?: string[];
  orderBy?: string;
  perPage?: number;
  status?: DiscountStatus[];
}