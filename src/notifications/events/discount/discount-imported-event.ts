/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */
import { Event } from '../../../entities/events/event';
import { Discount } from '../../../entities';
import { type IDiscountResponse, type IEventsResponse } from '../../../types';
import { EventName } from '../../helpers';

export class DiscountImportedEvent extends Event {
  public override readonly eventType = EventName.DiscountImported;
  public override readonly data: Discount;

  constructor(response: IEventsResponse<IDiscountResponse>) {
    super(response);
    this.data = new Discount(response.data);
  }
}