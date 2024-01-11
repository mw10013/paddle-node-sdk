/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */

import { type IProductResponse } from '../../types';
import { type CustomData, ImportMeta, Price } from '../index';
import { type CatalogType, type Status, type TaxCategory } from '../../enums';

export class ProductWithIncludes {
  public readonly id: string;
  public readonly name: string;
  public readonly type: CatalogType | null;
  public readonly description: string | null;
  public readonly taxCategory: TaxCategory;
  public readonly imageUrl: string | null;
  public readonly customData: CustomData | null;
  public readonly status: Status;
  public readonly createdAt: string;
  public readonly importMeta: ImportMeta | null;
  public readonly prices: Price[] | null;

  constructor(product: IProductResponse) {
    this.id = product.id;
    this.name = product.name;
    this.type = product.type ?? null;
    this.description = product.description ? product.description : null;
    this.taxCategory = product.tax_category;
    this.imageUrl = product.image_url ? product.image_url : null;
    this.customData = product.custom_data ? product.custom_data : null;
    this.status = product.status;
    this.createdAt = product.created_at;
    this.importMeta = product.import_meta ? new ImportMeta(product.import_meta) : null;
    this.prices = product.prices ? product.prices.map((price) => new Price(price)) : null;
  }
}