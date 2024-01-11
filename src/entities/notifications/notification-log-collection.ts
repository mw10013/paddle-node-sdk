/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */

import { Collection } from '../../internal/base';
import { type INotificationLogResponse } from '../../types';
import { NotificationLog } from './notification-log';

export class NotificationLogCollection extends Collection<INotificationLogResponse, NotificationLog> {
  override fromJson(data: INotificationLogResponse): NotificationLog {
    return new NotificationLog(data);
  }
}
