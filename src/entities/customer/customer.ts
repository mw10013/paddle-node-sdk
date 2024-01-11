/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */

import { type CustomData, ImportMeta } from '../index';
import { type Status } from '../../enums';
import { type ICustomerResponse } from '../../types';

export class Customer {
  public readonly id: string;
  public readonly name: string | null;
  public readonly email: string;
  public readonly marketingConsent: boolean;
  public readonly status: Status;
  public readonly customData: CustomData | null;
  public readonly locale: string;
  public readonly createdAt: string;
  public readonly updatedAt: string;
  public readonly importMeta: ImportMeta | null;

  constructor(customer: ICustomerResponse) {
    this.id = customer.id;
    this.name = customer.name ? customer.name : null;
    this.email = customer.email;
    this.marketingConsent = customer.marketing_consent;
    this.status = customer.status;
    this.customData = customer.custom_data ? customer.custom_data : null;
    this.locale = customer.locale;
    this.createdAt = customer.created_at;
    this.updatedAt = customer.updated_at;
    this.importMeta = customer.import_meta ? new ImportMeta(customer.import_meta) : null;
  }
}