import base64url from "base64url";
import crypto from "node:crypto";
import OAuth2Strategy from "passport-oauth2";
//@ts-ignore
import * as utils from "passport-oauth2/lib/utils.js";
import type { Request } from "express";
import type {
  ConsumableAPI,
  DiscordStrategyOptions,
  DiscordProfile,
  DoneCallback,
  ApplicationRoleConnectionMetadata,
  VerifyCallback,
} from "./types";

import { DiscordScope } from "./types";

import url from "node:url";

const API_BASE = "https://discord.com/api/";

/**
 * Represents the Discord OAuth2 strategy for Passport.
 * Extends the base OAuth2Strategy to provide custom behavior for Discord's API.
 * @param options - Configuration options for the strategy.
 * @throws Will throw an error if required options are missing.
 */

// * @param verify - Verification callback for the strategy.
class Strategy extends OAuth2Strategy {
  // @ts-ignore
  // private _verify:
  //   | VerifyFunction<DiscordProfile>
  //   | VerifyFunctionWithRequest<DiscordProfile>;
  // private _stateStore: any;
  // private _scope: any;
  // private _scopeSeparator: any;
  // private _pkceMethod: any;

  constructor(
    options: DiscordStrategyOptions,
    verify: (
      accessToken: string,
      refreshToken: string,
      profile: DiscordProfile,
      verified: VerifyCallback,
      consume: ConsumableAPI,
    ) => void,
  );
  constructor(
    options: DiscordStrategyOptions,
    verify: (
      req: Request,
      accessToken: string,
      refreshToken: string,
      results: DiscordProfile,
      profile: any,
      verified: VerifyCallback,
      consume: ConsumableAPI,
    ) => void,
  );
  constructor(
    private options: DiscordStrategyOptions,
    verify:
      | ((
          accessToken: string,
          refreshToken: string,
          profile: DiscordProfile,
          verified: VerifyCallback,
          consume: ConsumableAPI,
        ) => void)
      | ((
          accessToken: string,
          refreshToken: string,
          results: any,
          profile: DiscordProfile,
          verified: VerifyCallback,
          consume: ConsumableAPI,
        ) => void)
      | ((
          req: Request,
          accessToken: string,
          refreshToken: string,
          profile: DiscordProfile,
          verified: VerifyCallback,
          consume: ConsumableAPI,
        ) => void)
      | ((
          req: Request,
          accessToken: string,
          refreshToken: string,
          results: any,
          profile: DiscordProfile,
          verified: VerifyCallback,
          consume: ConsumableAPI,
        ) => void),
  ) {
    options = options || {};
    options.authorizationURL =
      options.authorizationURL || "https://discord.com/api/oauth2/authorize";
    options.tokenURL =
      options.tokenURL || "https://discord.com/api/oauth2/token";
    options.scopeSeparator = options.scopeSeparator || " ";
    options.scope = options.scope || [
      DiscordScope.Identify,
      DiscordScope.Email,
    ];

    if (!options.callbackURL) throw new Error("Missing callbackURL property");
    if (!options.clientID) throw new Error("Missing clientID property");
    if (!options.clientSecret) throw new Error("Missing clientSecret property");
    super(options, verify as any);

    this.options = options;
    // this.verify = verify;
    this.name = "discord";
    this._oauth2.useAuthorizationHeaderforGET(true);
  }

  /**
   * Fetches the user profile from Discord using the provided access token.
   * @param accessToken - The access token for the user.
   * @param [done] - Callback to handle the user profile.
   */

  override async userProfile(
    accessToken: string,
    done: (err: Error, result: null) => void,
  ): Promise<void>;

  override async userProfile(
    accessToken: string,
    done: (err: null, result: DiscordProfile) => void,
  ): Promise<void>;

  override async userProfile(
    accessToken: string,
    done: (err: any, result: any) => void,
  ): Promise<void> {
    try {
      const profile = (await this.resolveApi(
        "users/@me",
        accessToken,
      )) as DiscordProfile;
      const consumable = {
        guilds: this.getGuilds.bind(this, profile, accessToken),
        guildJoin: this.guildJoin.bind(this, profile, accessToken),
        connections: this.getConnection.bind(this, profile, accessToken),
        member: this.getMember.bind(this, profile, accessToken),
        linkedRole: {
          get: this.getRoleConnectionMetadata.bind(this, profile, accessToken),
          set: this.setRoleConnectionMetadata.bind(this, profile, accessToken),
        },
        // @ts-ignore
        complexResolver: this._oauth2._request,
        profile: () => profile,
        resolver: async (key: string, api: string) => {
          return new Promise(async (resolve, reject) => {
            try {
              const data: any = await this.resolveApi(api, accessToken);
              profile[key] = data;
              resolve(profile);
            } catch (err) {
              reject(err);
            }
          });
        },
      };
      profile.avatarUrl = profile.avatar
        ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}`
        : undefined;
      done(null, { profile, consumable } as any);
    } catch (e) {
      done(e instanceof Error ? e : new Error(String(e)), null);
    }
  }

  /**
   * Retrieves the connections associated with the user's Discord account.
   * @param {Object} profile - The user's profile.
   * @param {string} accessToken - The access token for the user.
   * @throws Will throw an error if the required scope is not included.
   */

  async getConnection(
    profile: DiscordProfile,
    accessToken: string,
    done?: DoneCallback,
  ): Promise<void> {
    if (
      !this.options.scope ||
      !this.options.scope.includes(DiscordScope.Connections)
    ) {
      throw new Error("Missing Scope, 'connections'");
    }

    try {
      const connections = await this.resolveApi(
        "users/@me/connections",
        accessToken,
      );
      profile["connections"] = connections;
      if (done) done(null, profile);
    } catch (e: any) {
      if (done) done(e instanceof Error ? e : new Error(String(e)), profile);
      else throw e;
    }
  }

  /**
   * Retrieves the guilds associated with the user's Discord account.
   * @param {Object} profile - The user's profile.
   * @param {string} accessToken - The access token for the user.
   * @throws Will throw an error if the required scope is not included.
   */
  async getGuilds(
    profile: DiscordProfile,
    accessToken: string,
    done?: DoneCallback,
  ): Promise<void> {
    if (
      !this.options.scope ||
      !this.options.scope.includes(DiscordScope.Guilds)
    ) {
      throw new Error("Missing Scope, 'guilds'");
    }

    try {
      const guilds = await this.resolveApi("users/@me/guilds", accessToken);
      profile["guilds"] = guilds;
      if (done) done(null, profile);
    } catch (e) {
      if (done) done(e instanceof Error ? e : new Error(String(e)), profile);
      else throw e;
    }
  }

  async getMember(
    profile: DiscordProfile,
    accessToken: string,
    guild_id: string,
    done?: DoneCallback,
  ): Promise<void> {
    if (
      !this.options.scope ||
      !this.options.scope.includes(DiscordScope.GuildsMembersRead)
    ) {
      throw new Error("Missing Scope, 'guilds.members.read'");
    }
    if (!profile["member"]) {
      profile["member"] = {};
    }

    // spaghetti code
    try {
      const member = await this.resolveApi(
        `users/@me/guilds/${guild_id}/member`,
        accessToken,
      );
      profile["member"][guild_id] = member;
      if (done) done(null, profile);
    } catch (e: any) {
      if (e.data?.code == 10004) {
        profile["member"][guild_id] = null;
      } else {
        if (done) done(e instanceof Error ? e : new Error(String(e)), profile);
        else throw e;
      }
    }
  }

  /**
   * Adds a user to a guild with the specified roles and nickname.
   * @param {Object} profile - The user's profile.
   * @param {string} accessToken - The access token for the user.
   * @param {string} botToken - The bot token for guild authorization.
   * @param {string} serverId - The ID of the server to join.
   * @param {string} nick - The nickname to assign to the user.
   * @param {string[]} roles - The roles to assign to the user.
   * @param {Function} done - Callback for handling the result.
   */
  async guildJoin(
    profile: DiscordProfile,
    accessToken: string,
    botToken: string,
    serverId: string,
    nick: string,
    roles: string[],
    done?: DoneCallback,
  ): Promise<void> {
    if (
      !this.options.scope ||
      !this.options.scope.includes(DiscordScope.GuildsJoin)
    ) {
      throw new Error("Missing Scope, 'guilds.join'");
    }

    const body = {
      access_token: accessToken,
      nick,
      roles,
    };

    try {
      const res: any = await new Promise((resolve, reject) => {
        // @ts-ignore
        this._oauth2._request(
          "PUT",
          `${API_BASE}guilds/${serverId}/members/${profile.id}`,
          {
            Authorization: `Bot ${botToken}`,
            "content-type": "application/json",
          },
          JSON.stringify(body),
          null,
          // @ts-ignore
          (err, result, response) => {
            if (err) {
              reject(err);
            } else {
              resolve(response);
            }
          },
        );
      });
      // @ts-ignore
      if (res.statusCode === 201 || res.statusCode === 204) {
        done?.(null, profile);
      } else {
        if (done) done(null, res.statusCode);
        else throw new Error(res.statusCode);
      }
    } catch (err) {
      if (done)
        done(err instanceof Error ? err : new Error(String(err)), profile);
      else throw err;
    }
  }

  /**
   * Retrieves the linked role metadata associated with the user's Discord account.
   * @param {string} profile - The user's profile.
   * @param {string} accessToken - The access token for the user.
   * @returns {Promise<Object>} The resolved data.
   * @throws Will throw an error for request or parsing issues.
   */
  async getRoleConnectionMetadata(
    profile: DiscordProfile,
    accessToken: string,
    done?: DoneCallback,
  ): Promise<void> {
    if (
      !this.options.scope ||
      !this.options.scope.includes(DiscordScope.RoleConnectionsWrite)
    ) {
      throw new Error("Missing Scope, 'role_connections.write'");
    }

    if (!profile["linkedRole"]) {
      profile["linkedRole"] = {};
    }

    try {
      const metadata = await this.resolveApi(
        `users/@me/applications/${this.options.clientID}/role-connection`,
        accessToken,
      );
      // doesn't it need to be parsed into js object????
      profile["linkedRole"].get = metadata; //todo!(): unknown??
      if (done) return done(null, profile);
    } catch (e) {
      if (done) done(e instanceof Error ? e : new Error(String(e)), profile);
      else throw e;
    }
  }

  /**
   * updated the linked role metadata associated with the user's Discord account.
   * @param {string} profile - The user's profile.
   * @param {string} accessToken - The access token for the user.
   * @param {string} platform_name - The vanity name of the platform a bot has connected (max 50 characters)
   * @param {string} platform_username - The username on the platform a bot has connected (max 100 characters)
   * @typedef {Object} metadata
   * @property {string} property1 - Description for property1.
   * @property {number} property2 - Description for property2.
   * @property {boolean} property3 - Description for property3.
   * @returns {Promise<Object>} The resolved data.
   * @throws Will throw an error for request or parsing issues.
   */
  async setRoleConnectionMetadata(
    profile: DiscordProfile,
    accessToken: string,
    platform_name: string,
    platform_username: string,
    metadata: ApplicationRoleConnectionMetadata,
    done?: DoneCallback,
  ): Promise<void> {
    if (
      !this.options.scope ||
      !this.options.scope.includes(DiscordScope.RoleConnectionsWrite)
    ) {
      throw new Error("Missing Scope, 'role_connections.write'");
    }
    if (!profile["linkedRole"]) {
      profile["linkedRole"] = {};
    }
    try {
      const role = await new Promise((resolve, reject) => {
        //@ts-ignore
        this._oauth2._request(
          "PUT",
          `${API_BASE}/users/@me/applications/${this.options.clientID}/role-connection`,
          {
            Authorization: `Bearer ${accessToken}`,
            "content-type": "application/json",
          },
          JSON.stringify({
            platform_name,
            platform_username,
            metadata,
          }),
          null,
          // @ts-ignore
          (err, result, response) => {
            if (err) {
              reject(err);
            } else {
              // huh? whats this??
              resolve(JSON.parse(result as any));
            }
          },
        );
      });
      profile["linkedRole"].set = role;
      if (done) return done(null, profile);
    } catch (e) {
      if (done) done(e instanceof Error ? e : new Error(String(e)), profile);
      else throw e;
    }
  }

  /**
   * Resolves an API endpoint and parses the response.
   * @param {string} api - The API endpoint to resolve.
   * @param {string} accessToken - The access token for the user.
   * @returns {Promise<Object>} The resolved data.
   * @throws Will throw an error for request or parsing issues.
   */
  async resolveApi(api: string, accessToken: string): Promise<unknown> {
    return new Promise(async (res, rej) => {
      try {
        const result = await new Promise((resolve, reject) => {
          this._oauth2.get(`${API_BASE}${api}`, accessToken, (err, result) => {
            if (err) {
              reject(err);
            } else {
              resolve(result);
            }
          });
        });
        res(JSON.parse(result as any));
      } catch (err) {
        // if (err instanceof SyntaxError) {
        //   rej(new Error("Failed to parse the user profile."));
        // }
        // throw new InternalOAuthError("Failed to resolve API", err);
        rej(err);
      }
    });
  }

  /**
   * Authenticate request by delegating to a service provider using OAuth 2.0.
   *
   * @param {Object} req
   * @api protected
   */
  override authenticate(req: any, options: any) {
    options = options || {};
    var self: any = this;

    if (req.query && req.query.error) {
      if (req.query.error == "access_denied") {
        return this.fail({ message: req.query.error_description });
      } else {
        return this.error(
          new Strategy.AuthorizationError(
            req.query.error_description,
            req.query.error,
            req.query.error_uri,
          ),
        );
      }
    }

    // @ts-ignore
    var callbackURL = options.callbackURL || this._callbackURL;
    if (callbackURL) {
      var parsed = url.URL.parse(callbackURL);
      if (!parsed?.protocol) {
        // The callback URL is relative, resolve a fully qualified URL from the
        // URL of the originating request.
        callbackURL = url.resolve(
          // @ts-ignore
          utils.originalURL(req, { proxy: this._trustProxy }),
          callbackURL,
        );
      }
    }

    var meta = {
      // @ts-ignore
      authorizationURL: this._oauth2._authorizeUrl,
      // @ts-ignore
      tokenURL: this._oauth2._accessTokenUrl,
      // @ts-ignore
      clientID: this._oauth2._clientId,
      callbackURL: callbackURL,
    };

    if ((req.query && req.query.code) || (req.body && req.body.code)) {
      function loaded(err: any, ok: any, state: any) {
        if (err) {
          return self.error(err);
        }
        if (!ok) {
          return self.fail(state, 403);
        }

        var code = (req.query && req.query.code) || (req.body && req.body.code);

        var params: any = self.tokenParams(options);

        params.grant_type = "authorization_code";
        if (callbackURL) {
          params.redirect_uri = callbackURL;
        }
        if (typeof ok == "string") {
          // PKCE
          params.code_verifier = ok;
        }

        self._oauth2.getOAuthAccessToken(
          code,
          params,
          function (
            err: any,
            accessToken: any,
            refreshToken: any,
            params: any,
          ) {
            if (err) {
              return self.error(
                self._createOAuthError("Failed to obtain access token", err),
              );
            }
            if (!accessToken) {
              return self.error(new Error("Failed to obtain access token"));
            }

            self._loadUserProfile(
              accessToken,
              function (
                err: Error,
                {
                  profile,
                  consumable,
                }: { profile: DiscordProfile; consumable: ConsumableAPI },
              ) {
                if (err) {
                  return self.error(err);
                }

                function verified(err: Error, user: any, info: any) {
                  if (err) {
                    return self.error(err);
                  }
                  if (!user) {
                    return self.fail(info);
                  }

                  info = info || {};
                  if (state) {
                    info.state = state;
                  }
                  self.success(user, info);
                }

                try {
                  if (self._passReqToCallback) {
                    // @ts-ignore

                    var arity = (self as Strategy)._verify.length;
                    if (arity == 7) {
                      self._verify(
                        req,
                        accessToken,
                        refreshToken,
                        params,
                        profile,
                        verified,
                        consumable,
                      );
                    } else {
                      // arity == 6
                      self._verify(
                        req,
                        accessToken,
                        refreshToken,
                        profile,
                        verified,
                        consumable,
                      );
                    }
                  } else {
                    var arity = self._verify.length as any as number;
                    if (arity == 6) {
                      self._verify(
                        accessToken,
                        refreshToken,
                        params,
                        profile,
                        verified,
                        consumable,
                      );
                    } else {
                      // arity == 5
                      self._verify(
                        accessToken,
                        refreshToken,
                        profile,
                        verified,
                        consumable,
                      );
                    }
                  }
                } catch (ex) {
                  return self.error(ex);
                }
              },
            );
          },
        );
      }

      var state =
        (req.query && req.query.state) || (req.body && req.body.state);
      try {
        // @ts-ignore
        var arity = this._stateStore.verify.length;
        if (arity == 4) {
          // @ts-ignore
          this._stateStore.verify(req, state, meta, loaded);
        } else {
          // arity == 3
          // @ts-ignore
          // @ts-ignore
          this._stateStore.verify(req, state, loaded);
        }
      } catch (ex) {
        return this.error(ex);
      }
    } else {
      var params = this.authorizationParams(options) as any;
      params.response_type = "code";
      if (callbackURL) {
        params.redirect_uri = callbackURL;
      }

      // @ts-ignore
      var scope = options.scope || this._scope;
      if (scope) {
        if (Array.isArray(scope)) {
          // @ts-ignore
          scope = scope.join(this._scopeSeparator);
        }
        params.scope = scope;
      }
      var verifier, challenge;

      // @ts-ignore
      if (this._pkceMethod) {
        verifier = base64url(crypto.pseudoRandomBytes(32));
        // @ts-ignore
        switch (this._pkceMethod) {
          case "plain":
            challenge = verifier;
            break;
          case "S256":
            challenge = base64url(
              crypto.createHash("sha256").update(verifier).digest(),
            );
            break;
          default:
            return this.error(
              new Error(
                "Unsupported code verifier transformation method: " +
                  // @ts-ignore
                  this._pkceMethod,
              ),
            );
        }
        params.code_challenge = challenge;
        // @ts-ignore
        params.code_challenge_method = this._pkceMethod;
      }

      var state = options.state;
      if (state && typeof state == "string") {
        // NOTE: In passport-oauth2@1.5.0 and earlier, `state` could be passed as
        //       an object.  However, it would result in an empty string being
        //       serialized as the value of the query parameter by `url.format()`,
        //       effectively ignoring the option.  This implies that `state` was
        //       only functional when passed as a string value.
        //
        //       This fact is taken advantage of here to fall into the `else`
        //       branch below when `state` is passed as an object.  In that case
        //       the state will be automatically managed and persisted by the
        //       state store.
        params.state = state;

        // @ts-ignore
        var parsed = url.parse((this._oauth2 as any)._authorizeUrl, true);
        // @ts-ignore
        utils.merge(parsed.query, params);
        // @ts-ignore
        parsed.query["client_id"] = this._oauth2._clientId;
        // @ts-ignore
        delete parsed.search;
        // @ts-ignore
        var location = url.format(parsed);
        this.redirect(location);
      } else {
        function stored(err: any, state: any) {
          if (err) {
            return self.error(err);
          }

          if (state) {
            // @ts-ignore
            params.state = state;
          }
          var parsed: any = url.parse(self._oauth2._authorizeUrl, true);
          utils.merge(parsed.query, params);
          parsed.query["client_id"] = self._oauth2._clientId;
          delete parsed.search;
          var location = url.format(parsed);
          self.redirect(location);
        }

        try {
          // @ts-ignore
          var arity = this._stateStore.store.length;
          if (arity == 6) {
            // @ts-ignore

            this._stateStore.store(req, verifier, state, meta, stored);
          } else if (arity == 5) {
            // @ts-ignore

            this._stateStore.store(req, state, meta, stored);
          } else if (arity == 4) {
            // @ts-ignore

            this._stateStore.store(req, meta, stored);
          } else {
            // @ts-ignore

            // arity == 3
            this._stateStore.store(req, stored);
          }
        } catch (ex) {
          return this.error(ex);
        }
      }
    }
  }
}

export { DiscordScope, Strategy };
export type { DiscordProfile, VerifyCallback, ConsumableAPI };
