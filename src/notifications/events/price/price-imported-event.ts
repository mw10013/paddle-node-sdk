/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */

import { Event } from '../../../entities/events/event';
import { Price } from '../../../entities';
import { EventName } from '../../helpers';
import { type IEventsResponse, type IPriceResponse } from '../../../types';

export class PriceImportedEvent extends Event {
  public override readonly eventType = EventName.PriceImported;
  public override readonly data: Price;

  constructor(response: IEventsResponse<IPriceResponse>) {
    super(response);
    this.data = new Price(response.data);
  }
}
