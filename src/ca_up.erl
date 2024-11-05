-module(ca_up).
-include_lib("public_key/include/public_key.hrl").
-export([init/2, reply/4, bind/2, echo/2, service/2, maybe_service/3]).

init(Req,Opts) ->
    Method  = cowboy_req:method(Req),
    HasBody = cowboy_req:has_body(Req),
    Request = maybe_service(Method, HasBody, Req),
    {ok, Request, Opts}.

reply(X,Y,Z,R)  -> cowboy_req:reply(X,Y,Z,R).
bind(X,Y)       -> binary_to_list(cowboy_req:binding(X,Y)).
echo(<<>>, Req) -> reply(400,#{},<<"General CA Sync Error">>,Req);
echo(Echo, Req) -> reply(200,#{<<"content-type">> => <<"text/plain;charset=utf-8">>},Echo,Req).

maybe_service(<<"POST">>, _, R) -> service(bind('crypto',R),R);
maybe_service(<<"GET">>, _, R)  -> service(bind('crypto',R),R);
maybe_service(_, _, R)          -> reply(405, #{}, <<"Unknown.">>, R).

service(Crypto,Req) ->
    {ok,PEM} = file:read_file("openssl/"++Crypto++"/caroot.pem"),
    {_,{_,D,_}} = lists:keysearch('Certificate',1,public_key:pem_decode(PEM)),
    OTPCert = public_key:pkix_decode_cert(D,otp),
    PKIInfo = OTPCert#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.subjectPublicKeyInfo,
    io:format("CA PUBLIC KEY [~s] ~p~n",[Crypto,PKIInfo]),
    echo(PEM,Req).
