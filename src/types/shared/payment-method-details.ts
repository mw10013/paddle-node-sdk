/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */

import { type IPaymentCardResponse } from '../index';
import { type PaymentType } from '../../enums';

export interface IPaymentMethodDetails {
  type: PaymentType;
  card?: IPaymentCardResponse | null;
}
