%% @doc A provider which fetches credentials from AWS STS.
%%
%% This provider checks if `AWS_WEB_IDENTITY_TOKEN_FILE' environment variable is set
%% and if so, fetches credentials from AWS STS. Overall, it uses the following
%% environment variables:
%%
%% <pre>
%% AWS_ROLE_ARN
%% AWS_ROLE_SESSION_NAME
%% AWS_WEB_IDENTITY_TOKEN_FILE
%% </pre>
%%
%% === Options ===
%%
%% * `sts_base_url' - The AWS STS base URL. Defaults to `"https://sts.amazonaws.com"'.
%%
%% @end
-module(aws_credentials_sts).
-behaviour(aws_credentials_provider).

-export([fetch/1]).

-spec fetch(any()) ->
        {ok, aws_credentials:credentials(), aws_credentials_provider:expiration()} |
        {error, any()}.
fetch(Options) ->
  case fetchenv("AWS_WEB_IDENTITY_TOKEN_FILE") of
    {ok, WebIdentityTokenFile} ->
      {ok, Contents} = file:read_file(WebIdentityTokenFile),
      WebIdentityToken = string:trim(Contents),
      {ok, RoleArn} = fetchenv("AWS_ROLE_ARN"),
      {ok, RoleSessionName} = fetchenv("AWS_ROLE_SESSION_NAME"),

      Query =
        "Action=AssumeRoleWithWebIdentity" ++
        "&Version=2011-06-15" ++
        "&RoleArn=" ++ RoleArn ++
        "&RoleSessionName=" ++ RoleSessionName ++
        "&WebIdentityToken=" ++ WebIdentityToken,
      BaseUrl = maps:get(sts_base_url, Options, "https://sts.amazonaws.com"),
      Url = BaseUrl ++ "?" ++ Query,
      ReqHeaders = [{"accept", "application/json"}],

      case aws_credentials_httpc:request(get, Url, ReqHeaders) of
        {ok, 200, Body, _Headers} ->
          #{
            <<"AssumeRoleWithWebIdentityResponse">> := #{
              <<"AssumeRoleWithWebIdentityResult">> := #{
                <<"Credentials">> := #{
                  <<"AccessKeyId">> := AccessKeyId,
                  <<"SecretAccessKey">> := SecretAccessKey,
                  <<"SessionToken">> := Token,
                  <<"Expiration">> := Expiration
                }
              }
            }
          } = jsx:decode(Body),
          Creds = aws_credentials:make_map(?MODULE, AccessKeyId, SecretAccessKey, Token),
          {ok, Creds, trunc(Expiration)};

        {ok, Status, Body, Headers} ->
          {error, {unexpected_http_response, {Status, Headers, Body}}};

        {error, Reason} ->
          {error, Reason}
      end;

    error ->
      {error, sts_credentials_unavailable}
  end.

-spec fetchenv(string()) -> {ok, string()} | error.
fetchenv(Name) ->
  case os:getenv(Name) of
    false -> error;
    Value -> {ok, Value}
  end.
