/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */
import { type INonCatalogPriceRequestBody } from '../price';

export interface ITransactionItemWithPriceId {
  priceId: string;
  price?: never;
  quantity: number;
}

export interface ITransactionItemWithPrice {
  priceId?: never;
  price: INonCatalogPriceRequestBody;
  quantity: number;
}

export type ITransactionItemWithNonCatalogPrice = ITransactionItemWithPriceId | ITransactionItemWithPrice;