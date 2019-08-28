-module(ca).
-compile(export_all).
-behaviour(application).
-behaviour(supervisor).
-export([start/2, stop/1, init/1]).

start(_StartType, _StartArgs) ->
   ca_enroll:boot("rsa"),
   ca_enroll:boot("ecc"),
   R = cowboy_router:compile([{'_', [{"/:crypto/:nsCertType", ca_enroll, []}]}]),
   {ok, _} = cowboy:start_clear(http,[{port,8046}],#{env => #{dispatch => R}}),
   supervisor:start_link({local, ?MODULE}, ?MODULE, []).
stop(_State) -> ok.
init([]) -> {ok, { {one_for_one, 5, 10}, []} }.
