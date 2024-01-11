import { type IEvents } from '../../types';
import {
  AddressCreatedEvent,
  AddressUpdatedEvent,
  AddressImportedEvent,
  AdjustmentCreatedEvent,
  AdjustmentUpdatedEvent,
  BusinessCreatedEvent,
  BusinessUpdatedEvent,
  CustomerCreatedEvent,
  CustomerUpdatedEvent,
  DiscountCreatedEvent,
  DiscountImportedEvent,
  DiscountUpdatedEvent,
  PayoutCreatedEvent,
  PayoutPaidEvent,
  PriceCreatedEvent,
  PriceUpdatedEvent,
  ProductCreatedEvent,
  ProductUpdatedEvent,
  ReportCreatedEvent,
  ReportUpdatedEvent,
  SubscriptionActivatedEvent,
  SubscriptionCanceledEvent,
  SubscriptionCreatedEvent,
  SubscriptionImportedEvent,
  SubscriptionPastDueEvent,
  SubscriptionPausedEvent,
  SubscriptionResumedEvent,
  SubscriptionTrialingEvent,
  SubscriptionUpdatedEvent,
  TransactionBilledEvent,
  TransactionCanceledEvent,
  TransactionCompletedEvent,
  TransactionCreatedEvent,
  TransactionPaidEvent,
  TransactionPastDueEvent,
  TransactionPaymentFailedEvent,
  TransactionReadyEvent,
  TransactionUpdatedEvent,
  BusinessImportedEvent,
  CustomerImportedEvent,
  PriceImportedEvent,
  ProductImportedEvent,
} from '../events';
import { type EventEntity, EventName } from './types';
import { WebhooksValidator } from './webhooks-validator';
import { Logger } from '../../internal/base/logger';

export class Webhooks {
  unmarshal(requestBody: string, secretKey: string, signature: string) {
    const isSignatureValid = new WebhooksValidator().isValidSignature(requestBody, secretKey, signature);

    if (isSignatureValid) {
      const parsedRequest = JSON.parse(requestBody);
      return Webhooks.fromJson(parsedRequest);
    } else {
      throw new Error('[Paddle] Webhook signature verification failed');
    }
  }

  isSignatureValid(requestBody: string, secretKey: string, signature: string) {
    return new WebhooksValidator().isValidSignature(requestBody, secretKey, signature);
  }

  static fromJson(data: IEvents): EventEntity | null {
    switch (data.event_type) {
      case EventName.AddressCreated:
        return new AddressCreatedEvent(data);
      case EventName.AddressUpdated:
        return new AddressUpdatedEvent(data);
      case EventName.AddressImported:
        return new AddressImportedEvent(data);
      case EventName.AdjustmentCreated:
        return new AdjustmentCreatedEvent(data);
      case EventName.AdjustmentUpdated:
        return new AdjustmentUpdatedEvent(data);
      case EventName.BusinessCreated:
        return new BusinessCreatedEvent(data);
      case EventName.BusinessUpdated:
        return new BusinessUpdatedEvent(data);
      case EventName.BusinessImported:
        return new BusinessImportedEvent(data);
      case EventName.CustomerCreated:
        return new CustomerCreatedEvent(data);
      case EventName.CustomerUpdated:
        return new CustomerUpdatedEvent(data);
      case EventName.CustomerImported:
        return new CustomerImportedEvent(data);
      case EventName.DiscountCreated:
        return new DiscountCreatedEvent(data);
      case EventName.DiscountImported:
        return new DiscountImportedEvent(data);
      case EventName.DiscountUpdated:
        return new DiscountUpdatedEvent(data);
      case EventName.PayoutCreated:
        return new PayoutCreatedEvent(data);
      case EventName.PayoutPaid:
        return new PayoutPaidEvent(data);
      case EventName.PriceCreated:
        return new PriceCreatedEvent(data);
      case EventName.PriceUpdated:
        return new PriceUpdatedEvent(data);
      case EventName.PriceImported:
        return new PriceImportedEvent(data);
      case EventName.ProductCreated:
        return new ProductCreatedEvent(data);
      case EventName.ProductUpdated:
        return new ProductUpdatedEvent(data);
      case EventName.ProductImported:
        return new ProductImportedEvent(data);
      case EventName.SubscriptionActivated:
        return new SubscriptionActivatedEvent(data);
      case EventName.SubscriptionCanceled:
        return new SubscriptionCanceledEvent(data);
      case EventName.SubscriptionCreated:
        return new SubscriptionCreatedEvent(data);
      case EventName.SubscriptionImported:
        return new SubscriptionImportedEvent(data);
      case EventName.SubscriptionPastDue:
        return new SubscriptionPastDueEvent(data);
      case EventName.SubscriptionPaused:
        return new SubscriptionPausedEvent(data);
      case EventName.SubscriptionResumed:
        return new SubscriptionResumedEvent(data);
      case EventName.SubscriptionTrialing:
        return new SubscriptionTrialingEvent(data);
      case EventName.SubscriptionUpdated:
        return new SubscriptionUpdatedEvent(data);
      case EventName.TransactionBilled:
        return new TransactionBilledEvent(data);
      case EventName.TransactionCanceled:
        return new TransactionCanceledEvent(data);
      case EventName.TransactionCompleted:
        return new TransactionCompletedEvent(data);
      case EventName.TransactionCreated:
        return new TransactionCreatedEvent(data);
      case EventName.TransactionPaid:
        return new TransactionPaidEvent(data);
      case EventName.TransactionPastDue:
        return new TransactionPastDueEvent(data);
      case EventName.TransactionPaymentFailed:
        return new TransactionPaymentFailedEvent(data);
      case EventName.TransactionReady:
        return new TransactionReadyEvent(data);
      case EventName.TransactionUpdated:
        return new TransactionUpdatedEvent(data);
      case EventName.ReportCreated:
        return new ReportCreatedEvent(data);
      case EventName.ReportUpdated:
        return new ReportUpdatedEvent(data);
      default:
        // @ts-expect-error event_type did not match any handled events
        Logger.log(`Unknown event_type ${data.event_type}`);
        return null;
    }
  }
}
