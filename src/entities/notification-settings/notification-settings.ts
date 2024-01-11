/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */
import { type NotificationSettingsType } from '../../enums';
import { EventType } from '../event-types';
import { type INotificationSettingsResponse } from '../../types/notification-settings';

export class NotificationSettings {
  public readonly id: string;
  public readonly description: string;
  public readonly type: NotificationSettingsType;
  public readonly destination: string;
  public readonly active: boolean;
  public readonly apiVersion: number;
  public readonly includeSensitiveFields: boolean;
  public readonly subscribedEvents: EventType[];
  public readonly endpointSecretKey: string;

  constructor(notificationSettings: INotificationSettingsResponse) {
    this.id = notificationSettings.id;
    this.description = notificationSettings.description;
    this.type = notificationSettings.type;
    this.destination = notificationSettings.destination;
    this.active = notificationSettings.active;
    this.apiVersion = notificationSettings.api_version;
    this.includeSensitiveFields = notificationSettings.include_sensitive_fields;
    this.subscribedEvents = notificationSettings.subscribed_events.map(
      (subscribed_event) => new EventType(subscribed_event),
    );
    this.endpointSecretKey = notificationSettings.endpoint_secret_key;
  }
}
