/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */

import { type IEventsResponse, type IAddressResponse } from '../../../types';

export const AddressUpdatedMock: IEventsResponse<IAddressResponse> = {
  event_id: 'evt_01h849k5rs5jxgctb45s6pmkat',
  event_type: 'address.updated',
  occurred_at: '2023-08-18T12:23:18.041154Z',
  notification_id: 'ntf_01h849k5vexw8kw4r74tm2w2g3',
  data: {
    id: 'add_01h849j51zpxv1e3zy2vgrrk6a',
    city: 'San Jose',
    region: 'CA',
    status: 'active',
    created_at: '2023-08-18T12:22:44.543Z',
    first_line: '5400 E Washington Drive, Floor 2',
    updated_at: '2023-08-18T12:23:17.773852Z',
    description: 'California Office',
    postal_code: '95314',
    second_line: null,
    country_code: 'US',
    custom_data: null,
  },
};

export const AddressUpdatedMockExpectation = {
  data: {
    city: 'San Jose',
    countryCode: 'US',
    createdAt: '2023-08-18T12:22:44.543Z',
    customData: null,
    description: 'California Office',
    firstLine: '5400 E Washington Drive, Floor 2',
    id: 'add_01h849j51zpxv1e3zy2vgrrk6a',
    importMeta: null,
    postalCode: '95314',
    region: 'CA',
    secondLine: null,
    status: 'active',
    updatedAt: '2023-08-18T12:23:17.773852Z',
  },
  eventId: 'evt_01h849k5rs5jxgctb45s6pmkat',
  eventType: 'address.updated',
  notificationId: 'ntf_01h849k5vexw8kw4r74tm2w2g3',
  occurredAt: '2023-08-18T12:23:18.041154Z',
};