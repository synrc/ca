-module(ca).
-description('CA: Certificate Authority').
-behaviour(application).
-behaviour(supervisor).
-export([start/2, stop/1, init/1]).

stop(_)    -> ok.
init([])   -> {ok, { {one_for_one, 5, 10}, []} }.
start(_,_) -> [ ca_enroll:boot(Crypto) || Crypto <- [ "rsa", "ecc" ] ],
              R = cowboy_router:compile([{'_', [
                  {"/up/:crypto", ca_up, []},
                  {"/enroll/:crypto/:nsCertType", ca_enroll, []}
              ]}]),
              {ok, _} = cowboy:start_clear(http,[{port,8046}],#{env => #{dispatch => R}}),
              supervisor:start_link({local, ?MODULE}, ?MODULE, []).
