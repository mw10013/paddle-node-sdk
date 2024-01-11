import {
  type AddressCreatedEvent,
  type AddressUpdatedEvent,
  type AddressImportedEvent,
  type BusinessCreatedEvent,
  type AdjustmentCreatedEvent,
  type AdjustmentUpdatedEvent,
  type BusinessUpdatedEvent,
  type CustomerCreatedEvent,
  type CustomerUpdatedEvent,
  type DiscountCreatedEvent,
  type DiscountImportedEvent,
  type DiscountUpdatedEvent,
  type PayoutCreatedEvent,
  type PayoutPaidEvent,
  type PriceCreatedEvent,
  type PriceUpdatedEvent,
  type ProductCreatedEvent,
  type ProductUpdatedEvent,
  type SubscriptionCreatedEvent,
  type SubscriptionActivatedEvent,
  type SubscriptionCanceledEvent,
  type SubscriptionImportedEvent,
  type SubscriptionPausedEvent,
  type SubscriptionResumedEvent,
  type SubscriptionTrialingEvent,
  type SubscriptionUpdatedEvent,
  type TransactionCanceledEvent,
  type TransactionBilledEvent,
  type TransactionCompletedEvent,
  type TransactionCreatedEvent,
  type TransactionPaidEvent,
  type SubscriptionPastDueEvent,
  type TransactionPastDueEvent,
  type TransactionPaymentFailedEvent,
  type TransactionReadyEvent,
  type TransactionUpdatedEvent,
  type ReportUpdatedEvent,
  type ReportCreatedEvent,
  type BusinessImportedEvent,
  type CustomerImportedEvent,
  type PriceImportedEvent,
  type ProductImportedEvent,
} from '../events';

export type EventEntity =
  | AddressCreatedEvent
  | AddressUpdatedEvent
  | AddressImportedEvent
  | AdjustmentUpdatedEvent
  | AdjustmentCreatedEvent
  | BusinessCreatedEvent
  | BusinessUpdatedEvent
  | BusinessImportedEvent
  | CustomerCreatedEvent
  | CustomerUpdatedEvent
  | CustomerImportedEvent
  | DiscountCreatedEvent
  | DiscountUpdatedEvent
  | DiscountImportedEvent
  | PayoutCreatedEvent
  | PayoutPaidEvent
  | PriceCreatedEvent
  | PriceUpdatedEvent
  | PriceImportedEvent
  | ProductCreatedEvent
  | ProductUpdatedEvent
  | ProductImportedEvent
  | SubscriptionActivatedEvent
  | SubscriptionCanceledEvent
  | SubscriptionCreatedEvent
  | SubscriptionImportedEvent
  | SubscriptionPastDueEvent
  | SubscriptionPausedEvent
  | SubscriptionResumedEvent
  | SubscriptionTrialingEvent
  | SubscriptionUpdatedEvent
  | TransactionBilledEvent
  | TransactionCanceledEvent
  | TransactionCompletedEvent
  | TransactionCreatedEvent
  | TransactionPaidEvent
  | TransactionPastDueEvent
  | TransactionPaymentFailedEvent
  | TransactionReadyEvent
  | TransactionUpdatedEvent
  | ReportUpdatedEvent
  | ReportCreatedEvent;

export enum EventName {
  AddressCreated = 'address.created',
  AddressUpdated = 'address.updated',
  AddressImported = 'address.imported',
  AdjustmentCreated = 'adjustment.created',
  AdjustmentUpdated = 'adjustment.updated',
  BusinessCreated = 'business.created',
  BusinessImported = 'business.imported',
  BusinessUpdated = 'business.updated',
  CustomerCreated = 'customer.created',
  CustomerUpdated = 'customer.updated',
  CustomerImported = 'customer.imported',
  DiscountCreated = 'discount.created',
  DiscountUpdated = 'discount.updated',
  DiscountImported = 'discount.imported',
  PayoutCreated = 'payout.created',
  PayoutPaid = 'payout.paid',
  PriceCreated = 'price.created',
  PriceUpdated = 'price.updated',
  PriceImported = 'price.imported',
  ProductCreated = 'product.created',
  ProductUpdated = 'product.updated',
  ProductImported = 'product.imported',
  SubscriptionActivated = 'subscription.activated',
  SubscriptionCanceled = 'subscription.canceled',
  SubscriptionImported = 'subscription.imported',
  SubscriptionCreated = 'subscription.created',
  SubscriptionPastDue = 'subscription.past_due',
  SubscriptionPaused = 'subscription.paused',
  SubscriptionResumed = 'subscription.resumed',
  SubscriptionTrialing = 'subscription.trialing',
  SubscriptionUpdated = 'subscription.updated',
  TransactionBilled = 'transaction.billed',
  TransactionCanceled = 'transaction.canceled',
  TransactionCompleted = 'transaction.completed',
  TransactionPaid = 'transaction.paid',
  TransactionCreated = 'transaction.created',
  TransactionPastDue = 'transaction.past_due',
  TransactionPaymentFailed = 'transaction.payment_failed',
  TransactionReady = 'transaction.ready',
  TransactionUpdated = 'transaction.updated',
  ReportCreated = 'report.created',
  ReportUpdated = 'report.updated',
}
export type IEventName =
  | 'address.created'
  | 'address.updated'
  | 'address.imported'
  | 'adjustment.created'
  | 'adjustment.updated'
  | 'business.created'
  | 'business.updated'
  | 'business.imported'
  | 'customer.created'
  | 'customer.updated'
  | 'discount.created'
  | 'discount.updated'
  | 'discount.imported'
  | 'payout.updated'
  | 'payout.paid'
  | 'price.updated'
  | 'price.created'
  | 'price.imported'
  | 'product.updated'
  | 'product.created'
  | 'product.imported'
  | 'subscription.activated'
  | 'subscription.canceled'
  | 'subscription.imported'
  | 'subscription.created'
  | 'subscription.past_due'
  | 'subscription.paused'
  | 'subscription.resumed'
  | 'subscription.trialing'
  | 'subscription.updated'
  | 'transaction.billed'
  | 'transaction.canceled'
  | 'transaction.completed'
  | 'transaction.paid'
  | 'transaction.created'
  | 'transaction.past_due'
  | 'transaction.payment_failed'
  | 'transaction.ready'
  | 'transaction.updated'
  | 'report.created'
  | 'report.updated';
