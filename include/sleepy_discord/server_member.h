#pragma once

#include "discord_object_interface.h"
#include "snowflake.h"
#include "user.h"

namespace SleepyDiscord {
/*Guild Member Structure
        Field     Type     Description
        user      object   user object
        nick      string?  this users guild nickname (if one is set)
        roles     array    array of role object id's
        joined_at datetime date the user joined the guild
        deaf      bool     if the user is deafened
        mute      bool     if the user is muted
        */
struct ServerMember : public IdentifiableDiscordObject<User> {
  ServerMember() = default;
  // ServerMember(const std::string * rawJson);
  ServerMember(const nonstd::string_view& rawJSON);
  ServerMember(const json::Value& json);
  // ServerMember(const json::Values values);
  User user;
  std::string nick;
  std::vector<Snowflake<Role>> roles;
  std::string joinedAt;
  bool deaf = false;
  bool mute = false;

  inline operator User&() { return user; }

  // const static std::initializer_list<const char*const> fields;
  JSONStructStart std::make_tuple(
      json::pair(&ServerMember::user, "user", json::OPTIONAL_FIELD),
      json::pair(&ServerMember::nick, "nick", json::OPTIONAL_FIELD),
      json::pair<json::ContainerTypeHelper>(&ServerMember::roles, "roles",
                                            json::OPTIONAL_FIELD),
      json::pair(&ServerMember::joinedAt, "joined_at", json::OPTIONAL_FIELD),
      json::pair(&ServerMember::deaf, "deaf", json::OPTIONAL_FIELD),
      json::pair(&ServerMember::mute, "mute", json::OPTIONAL_FIELD));
  JSONStructEnd
};

}  // namespace SleepyDiscord