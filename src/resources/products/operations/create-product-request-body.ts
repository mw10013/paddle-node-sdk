/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */

import { type ICustomData } from '../../../types';
import { type CatalogType, type TaxCategory } from '../../../enums';

export interface CreateProductRequestBody {
  name: string;
  taxCategory: TaxCategory;
  type?: CatalogType | null;
  description?: string | null;
  imageUrl?: string | null;
  customData?: ICustomData | null;
}