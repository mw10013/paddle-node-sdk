/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */
import { type IEventName } from '../../../notifications';

export interface UpdateNotificationSettingsRequestBody {
  description?: string;
  destination?: string;
  active?: boolean;
  apiVersion?: number;
  includeSensitiveFields?: boolean;
  subscribedEvents?: IEventName[];
}
