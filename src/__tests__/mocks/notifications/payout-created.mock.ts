/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */

import { type IEventsResponse, type IPayoutResponse } from '../../../types';

export const PayoutCreatedMock: IEventsResponse<IPayoutResponse> = {
  event_id: 'evt_01h2b06f69w9aw3eymqs1dfa2q',
  event_type: 'payout.created',
  occurred_at: '2023-06-01T13:30:38.138984Z',
  notification_id: 'ntf_01h2b06f84qsjzdw8rywe3j4gt',
  data: { id: 'pay_01gsz4vmqbjk3x4vvtafffd540', status: 'unpaid', amount: '10000', currency_code: 'USD' },
};

export const PayoutCreatedMockExpectation = {
  data: {
    amount: '10000',
    currencyCode: 'USD',
    id: 'pay_01gsz4vmqbjk3x4vvtafffd540',
    status: 'unpaid',
  },
  eventId: 'evt_01h2b06f69w9aw3eymqs1dfa2q',
  eventType: 'payout.created',
  notificationId: 'ntf_01h2b06f84qsjzdw8rywe3j4gt',
  occurredAt: '2023-06-01T13:30:38.138984Z',
};
