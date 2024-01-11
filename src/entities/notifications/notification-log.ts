/**
 *  ! Autogenerated code !
 *  Do not make changes to this file.
 *  Changes may be overwritten as part of auto-generation.
 */

export class NotificationLog {
  public readonly id: string;
  public readonly responseCode: number;
  public readonly responseContentType: string | null;
  public readonly responseBody: string;
  public readonly attemptedAt: string;

  constructor(notificationLogResponse: any) {
    this.id = notificationLogResponse.id;
    this.responseCode = notificationLogResponse.response_code;
    this.responseContentType = notificationLogResponse.response_content_type ?? null;
    this.responseBody = notificationLogResponse.response_body;
    this.attemptedAt = notificationLogResponse.attempted_at;
  }
}