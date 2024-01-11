/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */

import { type ICustomerBalance } from '../../types';

export class CustomerBalance {
  public readonly available: string;
  public readonly reserved: string;
  public readonly used: string;

  constructor(customerBalance: ICustomerBalance) {
    this.available = customerBalance.available;
    this.reserved = customerBalance.reserved;
    this.used = customerBalance.used;
  }
}