/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */

import { type ScheduledChangeAction } from '../../enums';

export interface ISubscriptionScheduledChangeResponse {
  action: ScheduledChangeAction;
  effective_at: string;
  resume_at?: string | null;
}
