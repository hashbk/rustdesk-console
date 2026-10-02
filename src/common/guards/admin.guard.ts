import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,

} from '@nestjs/common';
import { DataSource } from 'typeorm';
import { User, UserStatus } from '../../modules/user/entities/user.entity';
import { SystemSetting } from '../../modules/settings/entities/system-setting.entity';

// install_id storage contract, kept in sync with UpdateCheckService.
// install_id login is a transient admin user that is never persisted to the
// user table, so the database lookup below would always miss.
const INSTALL_ID_KEY = 'system.installId';
const INSTALL_ID_CATEGORY = 'system';
const LEGACY_INSTALL_ID_KEY = 'install_id';
const LEGACY_INSTALL_ID_CATEGORY = 'update_check';

@Injectable()
/**
 * AdminGuard
 * Verifies that the user has administrator privileges
 *
 * Permission rules:
 * Routes accessible only to administrators use this guard
 *
 * Validation logic:
 * Reads the current user status and isAdmin field from the database; does not trust the stale permission state inside the JWT.
 * The system install_id is treated as a transient administrator without a user row.
 */
export class AdminGuard implements CanActivate {

  constructor(private readonly dataSource: DataSource) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context
      .switchToHttp()
      .getRequest<{ user?: { id?: string } }>();
    const user = request.user;

    if (!user) {
      throw new ForbiddenException('Please log in first');
    }

    if (!user.id) {
      throw new ForbiddenException('Authorization service unavailable');
    }

    if (await this.isInstallIdUser(user.id)) {
      return true;
    }

    const currentUser = await this.dataSource.getRepository(User).findOne({
      where: { guid: user.id },
      select: ['guid', 'isAdmin', 'status'],
    });
    const isAdmin =
      currentUser?.isAdmin === true && currentUser.status === UserStatus.ACTIVE;

    if (!isAdmin) {
      throw new ForbiddenException(
        'Access denied: administrator privileges required',
      );
    }

    return true;
  }

  /**
   * Whether the given user guid is the system install_id.
   *
   * install_id is stored in system_settings under (category=system, key=installId),
   * with a legacy fallback (category=update_check, key=install_id). Lookup errors
   * are swallowed so the guard falls back to the regular database check.
   */
  private async isInstallIdUser(userGuid: string): Promise<boolean> {
    try {
      const repo = this.dataSource.getRepository(SystemSetting);
      const current = await repo.findOne({
        where: { key: INSTALL_ID_KEY, category: INSTALL_ID_CATEGORY },
      });
      if (current?.value === userGuid) return true;

      const legacy = await repo.findOne({
        where: {
          key: LEGACY_INSTALL_ID_KEY,
          category: LEGACY_INSTALL_ID_CATEGORY,
        },
      });
      return legacy?.value === userGuid;
    } catch {
      return false;
    }
  }
}
