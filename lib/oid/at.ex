defmodule CA.AT do
  @moduledoc "CA CSR Attributes OIDs."
  def oid(x) do
      case :lists.keyfind(x, 2, algorithms()) do
           {val,_} -> val
           false -> CA.ALG.oid(x)
      end
  end
  def algorithms() do
    [
      {:"id-at-rsaEncryption",                        {1, 2, 840, 113549, 1, 1, 1}},
      {:"id-at-sha1WithRSAEncryption",                {1, 2, 840, 113549, 1, 1, 5}},
      {:"id-at-sha512-256WithRSAEncryption",          {1, 2, 840, 113549, 1, 1, 16}},
      {:"id-at-dhKeyAgreement",                       {1, 2, 840, 113549, 1, 3, 1}},
      {:"id-at-emailAddress",                         {1, 2, 840, 113549, 1, 9, 1}},
      {:"id-at-unstructuredName",                     {1, 2, 840, 113549, 1, 9, 2}},
      {:"id-at-contentType",                          {1, 2, 840, 113549, 1, 9, 3}},
      {:"id-at-messageDigest",                        {1, 2, 840, 113549, 1, 9, 4}},
      {:"id-at-signingTime",                          {1, 2, 840, 113549, 1, 9, 5}},
      {:"id-at-counterSignature",                     {1, 2, 840, 113549, 1, 9, 6}},
      {:"id-at-challengePassword",                    {1, 2, 840, 113549, 1, 9, 7}},
      {:"id-at-unstructuredAddress",                  {1, 2, 840, 113549, 1, 9, 8}},
      {:"id-at-extendedCertificateAttributes",        {1, 2, 840, 113549, 1, 9, 9}},
      {:"id-at-issuerAndSerialNumber",                {1, 2, 840, 113549, 1, 9, 10}},
      {:"id-at-passwordCheck",                        {1, 2, 840, 113549, 1, 9, 11}},
      {:"id-at-publicKey",                            {1, 2, 840, 113549, 1, 9, 12}},
      {:"id-at-signingDescription",                   {1, 2, 840, 113549, 1, 9, 13}},
      {:"id-at-extensionRequest",                     {1, 2, 840, 113549, 1, 9, 14}},
      {:"id-at-smimeCapabilities",                    {1, 2, 840, 113549, 1, 9, 15}},
      {:"id-at-smime",                                {1, 2, 840, 113549, 1, 9, 16}},
      {:"id-aa",                                      {1, 2, 840, 113549, 1, 9, 16, 2}},
      {:"id-aa-timeStampToken",                       {1, 2, 840, 113549, 1, 9, 16, 2, 14}},
      {:"id-aa-ets-signerAttr",                       {1, 2, 840, 113549, 1, 9, 16, 2, 18}},
      {:"id-aa-ets-otherSigCert",                     {1, 2, 840, 113549, 1, 9, 16, 2, 19}},
      {:"id-aa-20",                                   {1, 2, 840, 113549, 1, 9, 16, 2, 20}},
      {:"id-aa-ets-CertificateRefs",                  {1, 2, 840, 113549, 1, 9, 16, 2, 21}},
      {:"id-aa-ets-revocationRefs",                   {1, 2, 840, 113549, 1, 9, 16, 2, 22}},
      {:"id-aa-ets-certValues",                       {1, 2, 840, 113549, 1, 9, 16, 2, 23}},
      {:"id-aa-ets-revocationValues",                 {1, 2, 840, 113549, 1, 9, 16, 2, 24}},
      {:"id-aa-signingCertificateV2",                 {1, 2, 840, 113549, 1, 9, 16, 2, 47}},
      {:"id-at-pgpKeyID",                             {1, 2, 840, 113549, 1, 9, 17}},
    ]
  end
end