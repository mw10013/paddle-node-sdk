/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */

import { type IEventsResponse, type IReportResponse } from '../../../types';

export const ReportUpdatedMock: IEventsResponse<IReportResponse> = {
  event_id: 'evt_01hhq4ck8bcaw47kyy3bk2vs8v',
  event_type: 'report.updated',
  occurred_at: '2023-12-15T16:19:10.219138Z',
  notification_id: 'nft_01hhjebfbgnrnyegsmcchyscxd',
  data: {
    id: 'rep_01hhq4c3b03g3x2kpkj8aecjv6',
    status: 'ready',
    rows: 10,
    type: 'transactions',
    filters: [
      { name: 'updated_at', value: '2023-12-15', operator: 'lt' },
      { name: 'updated_at', value: '2023-11-16', operator: 'gte' },
      { name: 'collection_mode', value: ['manual'], operator: null },
    ],
    expires_at: '2023-12-29T16:19:09.214771Z',
    created_at: '2023-12-15T16:18:53.92Z',
  },
};

export const ReportUpdatedMockExpectation = {
  data: {
    createdAt: '2023-12-15T16:18:53.92Z',
    expiresAt: '2023-12-29T16:19:09.214771Z',
    filters: [
      {
        name: 'updated_at',
        operator: 'lt',
        value: '2023-12-15',
      },
      {
        name: 'updated_at',
        operator: 'gte',
        value: '2023-11-16',
      },
      {
        name: 'collection_mode',
        operator: null,
        value: ['manual'],
      },
    ],
    id: 'rep_01hhq4c3b03g3x2kpkj8aecjv6',
    rows: 10,
    status: 'ready',
    type: 'transactions',
  },
  eventId: 'evt_01hhq4ck8bcaw47kyy3bk2vs8v',
  eventType: 'report.updated',
  notificationId: 'nft_01hhjebfbgnrnyegsmcchyscxd',
  occurredAt: '2023-12-15T16:19:10.219138Z',
};