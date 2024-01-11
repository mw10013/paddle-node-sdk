/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */

import { IEventsResponse } from '../../../types';
import { Response, ResponsePaginated } from '../../../internal';

export const EventMock: IEventsResponse = {
  event_id: 'evt_01hj32ak5egqkzw5hxrf3vjgw3',
  event_type: 'transaction.completed',
  occurred_at: '2023-12-20T07:34:00.622748Z',
  notification_id: 'ntf_1234',
  data: {
    id: 'txn_01hj327s2cpxh4mprx55p5qwdz',
    status: 'completed',
    customer_id: 'ctm_01hj3289s46amtzv8vr57xtnxp',
    address_id: 'add_01hj3289stgx73kjryne7pwzh7',
    business_id: null,
    custom_data: null,
    currency_code: 'USD',
    origin: 'web',
    subscription_id: 'sub_01hj32a99syawqhdkkbpxacwgb',
    invoice_id: 'inv_01hj32a9cjfk6zf1q81ke0xgex',
    invoice_number: '325-10335',
    collection_mode: 'automatic',
    discount_id: null,
    billing_details: null,
    billing_period: {
      ends_at: '2024-01-20T07:33:49.542313Z',
      starts_at: '2023-12-20T07:33:49.542313Z',
    },
    items: [
      {
        price: {
          id: 'pri_01gsz8x8sawmvhz1pv30nge1ke',
          type: 'standard',
          status: 'active',
          quantity: {
            maximum: 999,
            minimum: 1,
          },
          tax_mode: 'account_setting',
          product_id: 'pro_01gsz4t5hdjse780zja8vvr7jg',
          unit_price: {
            amount: '3000',
            currency_code: 'USD',
          },
          custom_data: {
            features: {
              crm: true,
              reports: true,
              data_retention: false,
            },
            suggested_addons: ['pro_01h1vjes1y163xfj1rh1tkfb65', 'pro_01gsz97mq9pa4fkyy0wqenepkz'],
            upgrade_description:
              "Move from Basic to Pro to take advantage of advanced reporting and a CRM that's right where you're chatting.",
          },
          description: 'Monthly (per seat)',
          trial_period: null,
          billing_cycle: {
            interval: 'month',
            frequency: 1,
          },
          unit_price_overrides: [
            {
              unit_price: {
                amount: '5000',
                currency_code: 'AUD',
              },
              country_codes: ['AU'],
            },
          ],
        },
        price_id: 'pri_01gsz8x8sawmvhz1pv30nge1ke',
        quantity: 10,
        proration: null,
      },
      {
        price: {
          id: 'pri_01h1vjfevh5etwq3rb416a23h2',
          type: 'standard',
          status: 'active',
          quantity: {
            maximum: 100,
            minimum: 1,
          },
          tax_mode: 'account_setting',
          product_id: 'pro_01h1vjes1y163xfj1rh1tkfb65',
          unit_price: {
            amount: '10000',
            currency_code: 'USD',
          },
          custom_data: null,
          description: 'Monthly (recurring addon)',
          trial_period: null,
          billing_cycle: {
            interval: 'month',
            frequency: 1,
          },
          unit_price_overrides: [
            {
              unit_price: {
                amount: '20000',
                currency_code: 'AUD',
              },
              country_codes: ['AU', 'AT', 'BE'],
            },
          ],
        },
        price_id: 'pri_01h1vjfevh5etwq3rb416a23h2',
        quantity: 1,
        proration: null,
      },
      {
        price: {
          id: 'pri_01gsz98e27ak2tyhexptwc58yk',
          type: 'standard',
          status: 'active',
          quantity: {
            maximum: 1,
            minimum: 1,
          },
          tax_mode: 'account_setting',
          product_id: 'pro_01gsz97mq9pa4fkyy0wqenepkz',
          unit_price: {
            amount: '19900',
            currency_code: 'USD',
          },
          custom_data: null,
          description: 'One-time charge',
          trial_period: null,
          billing_cycle: null,
          unit_price_overrides: [
            {
              unit_price: {
                amount: '40000',
                currency_code: 'AUD',
              },
              country_codes: ['AU'],
            },
          ],
        },
        price_id: 'pri_01gsz98e27ak2tyhexptwc58yk',
        quantity: 1,
        proration: null,
      },
    ],
    details: {
      totals: {
        fee: '3311',
        tax: '5315',
        total: '65215',
        credit: '0',
        balance: '0',
        discount: '0',
        earnings: '56589',
        subtotal: '59900',
        grand_total: '65215',
        currency_code: 'USD',
        credit_to_balance: '0',
      },
      line_items: [
        {
          id: 'txnitm_01hj328ac2ak7h82bjfzdk992c',
          totals: {
            tax: '2662',
            total: '32662',
            discount: '0',
            subtotal: '30000',
          },
          item_id: null,
          product: {
            id: 'pro_01gsz4t5hdjse780zja8vvr7jg',
            name: 'ChatApp Pro',
            type: 'standard',
            status: 'active',
            image_url: 'https://paddle-sandbox.s3.amazonaws.com/user/10889/2nmP8MQSret0aWeDemRw_icon1.png',
            custom_data: {
              features: {
                crm: true,
                reports: true,
                data_retention: false,
              },
              suggested_addons: ['pro_01h1vjes1y163xfj1rh1tkfb65', 'pro_01gsz97mq9pa4fkyy0wqenepkz'],
              upgrade_description:
                "Move from Basic to Pro to take advantage of advanced reporting and a CRM that's right where you're chatting.",
            },
            description:
              "Everything in basic, plus access to a suite of powerful tools and features designed to take your team's productivity to the next level.",
            tax_category: 'standard',
          },
          price_id: 'pri_01gsz8x8sawmvhz1pv30nge1ke',
          quantity: 10,
          tax_rate: '0.08875',
          unit_totals: {
            tax: '266',
            total: '3266',
            discount: '0',
            subtotal: '3000',
          },
        },
        {
          id: 'txnitm_01hj328ac2ak7h82bjg443x4px',
          totals: {
            tax: '887',
            total: '10887',
            discount: '0',
            subtotal: '10000',
          },
          item_id: null,
          product: {
            id: 'pro_01h1vjes1y163xfj1rh1tkfb65',
            name: 'Voice rooms addon',
            type: 'standard',
            status: 'active',
            image_url: 'https://paddle-sandbox.s3.amazonaws.com/user/10889/GcZzBjXRfiraensppgtQ_icon2.png',
            custom_data: null,
            description:
              'Create voice rooms in your chats to work in real time alongside your colleagues. Includes unlimited voice rooms and recording backup for compliance.',
            tax_category: 'standard',
          },
          price_id: 'pri_01h1vjfevh5etwq3rb416a23h2',
          quantity: 1,
          tax_rate: '0.08875',
          unit_totals: {
            tax: '887',
            total: '10887',
            discount: '0',
            subtotal: '10000',
          },
        },
        {
          id: 'txnitm_01hj328ac2ak7h82bjg8057m5r',
          totals: {
            tax: '1766',
            total: '21666',
            discount: '0',
            subtotal: '19900',
          },
          item_id: null,
          product: {
            id: 'pro_01gsz97mq9pa4fkyy0wqenepkz',
            name: 'Custom domains',
            type: 'standard',
            status: 'active',
            image_url: 'https://paddle-sandbox.s3.amazonaws.com/user/10889/SW3OevDQ92dUHSkN5a2x_icon3.png',
            custom_data: {
              crm_id: 'ABC',
            },
            description:
              'Make ChatApp truly your own with custom domains! Custom domains reinforce your brand identity and make it easy for your team to access ChatApp.',
            tax_category: 'standard',
          },
          price_id: 'pri_01gsz98e27ak2tyhexptwc58yk',
          quantity: 1,
          tax_rate: '0.08875',
          unit_totals: {
            tax: '1766',
            total: '21666',
            discount: '0',
            subtotal: '19900',
          },
        },
      ],
      payout_totals: {
        fee: '3311',
        tax: '5315',
        total: '65215',
        credit: '0',
        balance: '0',
        discount: '0',
        earnings: '56589',
        fee_rate: '0.05',
        subtotal: '59900',
        grand_total: '65215',
        currency_code: 'USD',
        exchange_rate: '1',
        credit_to_balance: '0',
      },
      tax_rates_used: [
        {
          totals: {
            tax: '5315',
            total: '65215',
            discount: '0',
            subtotal: '59900',
          },
          tax_rate: '0.08875',
        },
      ],
      adjusted_totals: {
        fee: '3311',
        tax: '5315',
        total: '65215',
        earnings: '56589',
        subtotal: '59900',
        grand_total: '65215',
        currency_code: 'USD',
      },
    },
    payments: [
      {
        amount: '65215',
        status: 'captured',
        created_at: '2023-12-20T07:33:43.097909Z',
        error_code: null,
        captured_at: '2023-12-20T07:33:49.542313Z',
        method_details: {
          card: {
            type: 'visa',
            last4: '4242',
            expiry_year: 2025,
            expiry_month: 1,
            cardholder_name: 'Michael McGovern',
          },
          type: 'card',
        },
        payment_attempt_id: 'b01f1321-289d-4932-b4af-6953e4910564',
        stored_payment_method_id: 'fea52bf9-57dc-4b06-88e2-ca15387a985a',
      },
    ],
    checkout: {
      url: 'https://magnificent-entremet-7ae0c6.netlify.app/default/overlay?_ptxn=txn_01hj327s2cpxh4mprx55p5qwdz',
    },
    created_at: '2023-12-20T07:32:28.436703Z',
    updated_at: '2023-12-20T07:33:59.31952849Z',
    billed_at: '2023-12-20T07:33:50.110917Z',
  },
};

export const EventMockResponse: Response<IEventsResponse> = {
  data: EventMock,
  meta: {
    request_id: '',
  },
};

export const ListEventMockResponse: ResponsePaginated<IEventsResponse> = {
  data: [EventMock],
  meta: {
    request_id: '',
    pagination: {
      estimated_total: 10,
      has_more: true,
      next: '/events?after=1',
      per_page: 10,
    },
  },
};
