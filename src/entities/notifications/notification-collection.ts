/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */

import { Collection } from '../../internal/base';
import { Notification } from './notification';
import { type INotificationResponse } from '../../types/notifications';

export class NotificationCollection extends Collection<INotificationResponse, Notification> {
  override fromJson(data: INotificationResponse): Notification {
    return new Notification(data);
  }
}