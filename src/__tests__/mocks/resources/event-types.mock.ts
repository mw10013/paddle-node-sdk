/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */

import { IEventTypeResponse } from '../../../types';
import { Response } from '../../../internal';

export const EventTypesMock: IEventTypeResponse[] = [
  {
    name: 'transaction.billed',
    description: 'Occurs when a transaction is billed. Its status field changes to billed and billed_at is populated.',
    group: 'Transaction',
    available_versions: [1],
  },
  {
    name: 'transaction.canceled',
    description: 'Occurs when a transaction is canceled. Its status field changes to canceled.',
    group: 'Transaction',
    available_versions: [1],
  },
  {
    name: 'transaction.completed',
    description: 'Occurs when a transaction is completed. Its status field changes to completed.',
    group: 'Transaction',
    available_versions: [1],
  },
  {
    name: 'transaction.created',
    description: 'Occurs when a transaction is created.',
    group: 'Transaction',
    available_versions: [1],
  },
  {
    name: 'transaction.past_due',
    description: 'Occurs when a transaction becomes past due. Its status field changes to past_due.',
    group: 'Transaction',
    available_versions: [1],
  },
  {
    name: 'transaction.payment_failed',
    description:
      'Occurs when a payment fails for a transaction. The payments array is updated with details of the payment attempt.',
    group: 'Transaction',
    available_versions: [1],
  },
  {
    name: 'transaction.ready',
    description: 'Occurs when a transaction is ready to be billed. Its status field changes to ready.',
    group: 'Transaction',
    available_versions: [1],
  },
  {
    name: 'transaction.updated',
    description: 'Occurs when a transaction is updated.',
    group: 'Transaction',
    available_versions: [1],
  },
  {
    name: 'subscription.activated',
    description:
      'Occurs when a subscription becomes active. Its status field changes to active. This means any trial period has elapsed and Paddle has successfully billed the customer.',
    group: 'Subscription',
    available_versions: [1],
  },
  {
    name: 'subscription.canceled',
    description: 'Occurs when a subscription is canceled. Its status field changes to canceled.',
    group: 'Subscription',
    available_versions: [1],
  },
  {
    name: 'subscription.created',
    description:
      'Occurs when a subscription is created. subscription.trialing or subscription.activated typically follow.',
    group: 'Subscription',
    available_versions: [1],
  },
  {
    name: 'subscription.imported',
    description: 'Occurs when a subscription is imported.',
    group: 'Subscription',
    available_versions: [1],
  },
  {
    name: 'subscription.past_due',
    description: 'Occurs when a subscription has an unpaid transaction. Its status changes to past_due.',
    group: 'Subscription',
    available_versions: [1],
  },
  {
    name: 'subscription.paused',
    description: 'Occurs when a subscription is paused. Its status field changes to paused.',
    group: 'Subscription',
    available_versions: [1],
  },
  {
    name: 'subscription.resumed',
    description: 'Occurs when a subscription is resumed after being paused. Its status field changes to active.',
    group: 'Subscription',
    available_versions: [1],
  },
  {
    name: 'subscription.trialing',
    description: 'Occurs when a subscription enters trial period.',
    group: 'Subscription',
    available_versions: [1],
  },
  {
    name: 'subscription.updated',
    description: 'Occurs when a subscription is updated.',
    group: 'Subscription',
    available_versions: [1],
  },
  {
    name: 'product.created',
    description: 'Occurs when a product is created.',
    group: 'Product',
    available_versions: [1],
  },
  {
    name: 'product.updated',
    description: 'Occurs when a product is updated.',
    group: 'Product',
    available_versions: [1],
  },
  {
    name: 'price.created',
    description: 'Occurs when a price is created.',
    group: 'Price',
    available_versions: [1],
  },
  {
    name: 'price.updated',
    description: 'Occurs when a price is updated.',
    group: 'Price',
    available_versions: [1],
  },
  {
    name: 'discount.created',
    description: 'Occurs when a discount is created.',
    group: 'Discount',
    available_versions: [1],
  },
  {
    name: 'discount.updated',
    description: 'Occurs when a discount is updated.',
    group: 'Discount',
    available_versions: [1],
  },
  {
    name: 'customer.created',
    description: 'Occurs when a customer is created.',
    group: 'Customer',
    available_versions: [1],
  },
  {
    name: 'customer.updated',
    description: 'Occurs when a customer is updated.',
    group: 'Customer',
    available_versions: [1],
  },
  {
    name: 'address.created',
    description: 'Occurs when an address is created.',
    group: 'Address',
    available_versions: [1],
  },
  {
    name: 'address.updated',
    description: 'Occurs when an address is updated.',
    group: 'Address',
    available_versions: [1],
  },
  {
    name: 'business.created',
    description: 'Occurs when a business is created.',
    group: 'Business',
    available_versions: [1],
  },
  {
    name: 'business.updated',
    description: 'Occurs when a business is updated.',
    group: 'Business',
    available_versions: [1],
  },
  {
    name: 'adjustment.created',
    description: 'Occurs when an adjustment is created.',
    group: 'Adjustment',
    available_versions: [1],
  },
  {
    name: 'adjustment.updated',
    description:
      'Occurs when an adjustment is updated, the only time an adjustment will be updated is when the status changes from pending to approved or from pending to rejected.',
    group: 'Adjustment',
    available_versions: [1],
  },
];

export const ListEventTypeMockResponse: Response<IEventTypeResponse[]> = {
  data: EventTypesMock,
  meta: {
    request_id: '',
  },
};
