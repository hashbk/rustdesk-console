import {
  Injectable,
  Logger,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import { User, UserStatus } from '../../user/entities/user.entity';
import { UpdateCheckService } from '../../update-check/update-check.service';
import { UserGroupService } from '../../user-group/user-group.service';
import { LoginDto } from '../dto/auth.dto';

/**
 * install_id 登录服务
 *
 * 允许使用系统 install_id 同时作为用户名和密码进行登录。
 * 登录时自动查找或创建一个与 install_id 关联的管理员账户，
 * 该账户无需邮箱验证、无需 TFA，直接发放访问令牌。
 */
@Injectable()
export class AuthInstallIdService {
  private readonly logger = new Logger(AuthInstallIdService.name);

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly updateCheckService: UpdateCheckService,
    private readonly userGroupService: UserGroupService,
  ) {}

  /**
   * 处理 install_id 登录
   *
   * 校验 username 与 password 均等于系统 install_id，
   * 通过后查找或创建对应的管理员用户并返回。
   *
   * @param loginDto 登录请求
   * @returns 与 install_id 关联的管理员用户
   * @throws BadRequestException 当用户名或密码缺失时
   * @throws UnauthorizedException 当用户名或密码与 install_id 不匹配时
   */
  async login(loginDto: LoginDto): Promise<User> {
    const { username, password } = loginDto;

    if (!username || !password) {
      throw new BadRequestException({ error: '用户名和密码不能为空' });
    }

    const installId = await this.updateCheckService.getInstallId();

    if (username !== installId || password !== installId) {
      throw new UnauthorizedException({ error: '用户名或密码错误' });
    }

    const user = await this.findOrCreateInstallIdUser(installId);

    this.logger.log(`install_id 登录成功: ${user.username}`);

    return user;
  }

  /**
   * 查找或创建与 install_id 关联的管理员用户
   *
   * 首次使用 install_id 登录时自动创建一个管理员账户，
   * 后续登录复用该账户。密码存储为 install_id 的哈希值，
   * 使该账户也可通过标准账号密码流程登录。
   */
  private async findOrCreateInstallIdUser(installId: string): Promise<User> {
    const existing = await this.userRepository.findOne({
      where: { username: installId },
    });

    if (existing) {
      return existing;
    }

    const hashedPassword = await bcrypt.hash(installId, 10);
    const userGroupGuid = await this.userGroupService.resolveUserGroupGuid();

    const user = this.userRepository.create({
      guid: uuidv4(),
      username: installId,
      email: null,
      password: hashedPassword,
      note: 'install_id auto-created admin',
      status: UserStatus.ACTIVE,
      isAdmin: true,
      userGroupGuid,
    });

    await this.userRepository.save(user);

    this.logger.log(`install_id 管理员用户已创建: ${user.guid}`);

    return user;
  }
}