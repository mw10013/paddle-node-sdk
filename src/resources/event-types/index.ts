/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */

import { BaseResource } from '../../internal/base';
import { type ErrorResponse, type Response } from '../../internal';
import { type IEventTypeResponse } from '../../types';
import { EventType } from '../../entities';

const EventTypesPaths = {
  list: '/event-types',
} as const;

export class EventTypesResource extends BaseResource {
  public async list(): Promise<EventType[]> {
    const response = await this.client.get<undefined, Response<IEventTypeResponse[]> | ErrorResponse>(
      EventTypesPaths.list,
    );

    const data = this.handleResponse<IEventTypeResponse[]>(response);

    return data.map((eventType) => new EventType(eventType));
  }
}
