import type OAuth2Strategy from "passport-oauth2";
import type { OutgoingHttpHeaders, IncomingMessage } from "node:http";
/**
 * Represents a Discord user's avatar decoration.
 */
export interface AvatarDecorationData {
  /** The avatar decoration hash. */
  asset: string;

  /** The ID of the avatar decoration's SKU. */
  sku_id: string;
}

/**
 * Represents a Discord nameplate.
 */
export interface Nameplate {
  /** ID of the nameplate SKU. */
  sku_id: string;

  /** Path to the nameplate asset. */
  asset: string;

  /** The label of this nameplate. Currently unused. */
  label: string;

  /** Background color of the nameplate. One of: crimson, berry, sky, teal, forest, bubble_gum, violet, cobalt, clover, lemon, white */
  palette:
    | "crimson"
    | "berry"
    | "sky"
    | "teal"
    | "forest"
    | "bubble_gum"
    | "violet"
    | "cobalt"
    | "clover"
    | "lemon"
    | "white";
}

/**
 * Represents Discord collectibles for a user.
 */
export interface Collectibles {
  /** Optional object mapping of nameplate data. */
  nameplate?: Nameplate;
}

/**
 * Represents a user's primary guild.
 */
export interface UserPrimaryGuild {
  /** The ID of the user's primary guild. */
  identity_guild_id?: string;

  /** Whether the user is displaying the primary guild's server tag. */
  identity_enabled?: boolean;

  /** The text of the user's server tag, limited to 4 characters. */
  tag?: string;

  /** The server tag badge hash. */
  badge?: string;
}

// todo!(): Link discord profile with scope passed?

/**
 * Represents a Discord user object returned by the OAuth2 API.
 */
export interface DiscordProfile {
  /** The user's unique ID (snowflake). */
  id: string;

  /** The user's username, not unique across the platform. */
  username: string;

  /** The user's Discord tag (discriminator). */
  discriminator: string;

  /** The user's display name, if set. For bots, this is the application name. */
  global_name?: string;

  /** The user's avatar hash. */
  avatar?: string;

  /** The user's avatar url. */
  avatarUrl?: string | undefined;

  /** Whether the user belongs to an OAuth2 application (bot). */
  bot?: boolean;

  /** Whether the user is an Official Discord System user (part of the urgent message system). */
  system?: boolean;

  /** Whether the user has two-factor authentication enabled. */
  mfa_enabled?: boolean;

  /** The user's banner hash. */
  banner?: string;

  /** The user's banner color encoded as an integer representation of a hexadecimal color code. */
  accent_color?: number;

  /** The user's chosen language option (locale). */
  locale?: string;

  /** Whether the email on this account has been verified. */
  verified?: boolean;

  /** The user's email. */
  email?: string;

  /** The flags on the user's account. */
  flags?: number;

  /** The type of Nitro subscription on the user's account. */
  premium_type?: number;

  /** The public flags on the user's account. */
  public_flags?: number;

  /** Data for the user's avatar decoration. */
  avatar_decoration_data?: AvatarDecorationData;

  /** Data for the user's collectibles. */
  collectibles?: Collectibles;

  /** The user's primary guild. */
  primary_guild?: UserPrimaryGuild;

  [key: string]: any;
}

export interface ConsumableAPI {
  guilds: (done?: DoneCallback) => Promise<void>;
  guildJoin: (
    botToken: string,
    serverId: string,
    nick: string,
    roles: string[],
    done?: DoneCallback,
  ) => Promise<any>;
  connections: (done?: DoneCallback) => Promise<void>;
  member: (guildId: string, done?: DoneCallback) => Promise<void>;
  linkedRole: {
    get: (done?: DoneCallback) => Promise<void>;
    set: (
      platform_name: string,
      platform_username: string,
      metadata: ApplicationRoleConnectionMetadata,
      done?: DoneCallback,
    ) => Promise<void>;
  };
  complexResolver: (
    method: string,
    url: string,
    headers: OutgoingHttpHeaders | null,
    post_body: any,
    access_token: string | null,
    callback: (
      err: { statusCode: number; data?: any },
      result?: string | Buffer,
      response?: IncomingMessage,
    ) => any,
  ) => void; // Reference to this._oauth2._request
  profile: () => DiscordProfile;
  resolver: (key: string, api: string) => Promise<any>;
}

export type DoneCallback = (err: Error | null, result: DiscordProfile) => void;

export interface StrategyFetchResult {
  profile: DiscordProfile;
}

export interface DiscordStrategyOptions extends Omit<OAuth2Strategy.StrategyOptions, "authorizationURL" | "tokenURL"> {
  authorizationURL?: string;
  tokenURL?: string;
  scope?: DiscordScope[];
}

export enum DiscordScope {
  ActivitiesRead = "activities.read",
  ActivitiesWrite = "activities.write",
  ApplicationsBuildsRead = "applications.builds.read",
  ApplicationsBuildsUpload = "applications.builds.upload",
  ApplicationsCommands = "applications.commands",
  ApplicationsCommandsUpdate = "applications.commands.update",
  ApplicationsCommandsPermissionsUpdate = "applications.commands.permissions.update",
  ApplicationsEntitlements = "applications.entitlements",
  ApplicationsStoreUpdate = "applications.store.update",
  Bot = "bot",
  Connections = "connections",
  DMChannelsRead = "dm_channels.read",
  Email = "email",
  GroupDMJoin = "gdm.join",
  Guilds = "guilds",
  GuildsJoin = "guilds.join",
  GuildsMembersRead = "guilds.members.read",
  Identify = "identify",
  MessagesRead = "messages.read",
  RelationshipsRead = "relationships.read",
  RoleConnectionsWrite = "role_connections.write",
  RPC = "rpc",
  RPCActivitiesWrite = "rpc.activities.write",
  RPCNotificationsRead = "rpc.notifications.read",
  RPCVoiceRead = "rpc.voice.read",
  RPCVoiceWrite = "rpc.voice.write",
  Voice = "voice",
  WebhookIncoming = "webhook.incoming",
}

/**
 * Represents a metadata field for an application role connection.
 */
export interface ApplicationRoleConnectionMetadata {
  /**
   * The type of metadata value.
   */
  type: ApplicationRoleConnectionMetadataType;

  /**
   * The key of the metadata field.
   * Must contain only lowercase letters (a-z), numbers (0-9), or underscores (_),
   * and be between 1 and 50 characters.
   */
  key: string;

  /**
   * The name of the metadata field.
   * Must be between 1 and 100 characters.
   */
  name: string;

  /**
   * Optional localized translations of the name.
   * Keys are locale identifiers (e.g., "en-US", "fr-FR").
   */
  name_localizations?: Record<string, string>;

  /**
   * A description of the metadata field.
   * Must be between 1 and 200 characters.
   */
  description: string;

  /**
   * Optional localized translations of the description.
   * Keys are locale identifiers (e.g., "en-US", "fr-FR").
   */
  description_localizations?: Record<string, string>;
}

/**
 * Enum representing the type of metadata value for role connections.
 */
export enum ApplicationRoleConnectionMetadataType {
  /** The metadata value (integer) is less than or equal to the guild's configured value. */
  INTEGER_LESS_THAN_OR_EQUAL = 1,

  /** The metadata value (integer) is greater than or equal to the guild's configured value. */
  INTEGER_GREATER_THAN_OR_EQUAL = 2,

  /** The metadata value (integer) is equal to the guild's configured value. */
  INTEGER_EQUAL = 3,

  /** The metadata value (integer) is not equal to the guild's configured value. */
  INTEGER_NOT_EQUAL = 4,

  /** The metadata value (ISO8601 string) is less than or equal to the guild's configured value (days before current date). */
  DATETIME_LESS_THAN_OR_EQUAL = 5,

  /** The metadata value (ISO8601 string) is greater than or equal to the guild's configured value (days before current date). */
  DATETIME_GREATER_THAN_OR_EQUAL = 6,

  /** The metadata value (integer) is equal to the guild's configured value (boolean 1). */
  BOOLEAN_EQUAL = 7,

  /** The metadata value (integer) is not equal to the guild's configured value (boolean 1). */
  BOOLEAN_NOT_EQUAL = 8,
}

export type VerifyCallback = (
  err?: Error | null | unknown,
  user?: Express.User | false,
  info?: object,
) => void;

export type VerifyFunction<TProfile = any, TResults = any> =
  | ((
      accessToken: string,
      refreshToken: string,
      profile: TProfile,
      verified: VerifyCallback,
      consume: ConsumableAPI,
    ) => void)
  | ((
      accessToken: string,
      refreshToken: string,
      results: TResults,
      profile: TProfile,
      verified: VerifyCallback,
      consume: ConsumableAPI,
    ) => void);
export type VerifyFunctionWithRequest<TProfile = any, TResults = any> =
  | ((
      req: Request,
      accessToken: string,
      refreshToken: string,
      profile: TProfile,
      verified: VerifyCallback,
      consume: ConsumableAPI,
    ) => void)
  | ((
      req: Request,
      accessToken: string,
      refreshToken: string,
      results: TResults,
      profile: TProfile,
      verified: VerifyCallback,
      consume: ConsumableAPI,
    ) => void);
