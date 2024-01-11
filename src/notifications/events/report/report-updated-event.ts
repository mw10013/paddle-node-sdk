/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */

import { Event } from '../../../entities/events/event';
import { Report } from '../../../entities';
import { EventName } from '../../helpers';
import { type IEventsResponse, type IReportResponse } from '../../../types';

export class ReportUpdatedEvent extends Event {
  public override readonly eventType = EventName.ReportUpdated;
  public override readonly data: Report;

  constructor(response: IEventsResponse<IReportResponse>) {
    super(response);
    this.data = new Report(response.data);
  }
}
