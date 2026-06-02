defmodule CA.CP do
  @moduledoc "CA Certificate Policies OIDs for Ukraine Court Systems."

  def oid(:"id-cp-ua-court-basic"),                       do: {1, 2, 804, 3, 1, 2, 1}
  def oid(:"id-cp-ua-court-branch"),                      do: {1, 2, 804, 3, 1, 2, 2}
  def oid(:"id-cp-ua-court-supreme"),                     do: {1, 2, 804, 3, 1, 2, 3}
  def oid(:"id-cp-ua-court-supreme-grand-chamber"),       do: {1, 2, 804, 3, 1, 2, 3, 1}
  def oid(:"id-cp-ua-court-supreme-admin"),               do: {1, 2, 804, 3, 1, 2, 3, 2}
  def oid(:"id-cp-ua-court-supreme-commercial"),          do: {1, 2, 804, 3, 1, 2, 3, 3}
  def oid(:"id-cp-ua-court-supreme-criminal"),            do: {1, 2, 804, 3, 1, 2, 3, 4}
  def oid(:"id-cp-ua-court-supreme-civil"),               do: {1, 2, 804, 3, 1, 2, 3, 5}
  def oid(:"id-cp-ua-court-specialized"),                 do: {1, 2, 804, 3, 1, 2, 4}
  def oid(:"id-cp-ua-court-ip"),                          do: {1, 2, 804, 3, 1, 2, 4, 1}
  def oid(:"id-cp-ua-court-anti-corruption"),             do: {1, 2, 804, 3, 1, 2, 4, 2}
  def oid(:"id-cp-ua-court-specialized-admin-district"),  do: {1, 2, 804, 3, 1, 2, 4, 3}
  def oid(:"id-cp-ua-court-specialized-admin-appeal"),    do: {1, 2, 804, 3, 1, 2, 4, 4}
  def oid(:"id-cp-ua-court-target"),                      do: {1, 2, 804, 3, 1, 2, 5}
  def oid(:"id-cp-ua-court-local"),                       do: {1, 2, 804, 3, 1, 2, 5, 1}
  def oid(:"id-cp-ua-court-appeal"),                      do: {1, 2, 804, 3, 1, 2, 5, 2}
  def oid(:"id-cp-ua-court-orgs"),                        do: {1, 2, 804, 3, 1, 2, 6}
  def oid(:"id-cp-ua-court-dsa"),                         do: {1, 2, 804, 3, 1, 2, 6, 1}
  def oid(:"id-cp-ua-court-tu-dsa"),                      do: {1, 2, 804, 3, 1, 2, 6, 2}
  def oid(:"id-cp-ua-court-rsu"),                         do: {1, 2, 804, 3, 1, 2, 6, 3}
  def oid(:"id-cp-ua-court-vrp"),                         do: {1, 2, 804, 3, 1, 2, 6, 4}
  def oid(:"id-cp-ua-court-vkksu"),                       do: {1, 2, 804, 3, 1, 2, 6, 5}
  def oid(:"id-cp-ua-court-nshsu"),                       do: {1, 2, 804, 3, 1, 2, 6, 6}
  def oid(:"id-cp-ua-court-grd-grme"),                    do: {1, 2, 804, 3, 1, 2, 6, 7}
  def oid(:"id-cp-ua-court-sso"),                         do: {1, 2, 804, 3, 1, 2, 6, 8}

  def lookup({1, 2, 804, 3, 1, 2, 1}), do: "Базовий профіль безпеки (Level 1)"
  def lookup({1, 2, 804, 3, 1, 2, 2}), do: "Галузевий профіль безпеки (Level 2)"
  def lookup({1, 2, 804, 3, 1, 2, 3}), do: "Цільовий профіль безпеки вищих судів (Level 3)"
  def lookup({1, 2, 804, 3, 1, 2, 3, 1}), do: "Велика Палата Верховного Суду"
  def lookup({1, 2, 804, 3, 1, 2, 3, 2}), do: "Касаційний адміністративний суд"
  def lookup({1, 2, 804, 3, 1, 2, 3, 3}), do: "Касаційний господарський суд"
  def lookup({1, 2, 804, 3, 1, 2, 3, 4}), do: "Касаційний кримінальний суд"
  def lookup({1, 2, 804, 3, 1, 2, 3, 5}), do: "Касаційний цивільний суд"
  def lookup({1, 2, 804, 3, 1, 2, 4}), do: "Цільовий профіль безпеки вищих спеціалізованих судів (Level 3)"
  def lookup({1, 2, 804, 3, 1, 2, 4, 1}), do: "Вищий суд з питань інтелектуальної власності"
  def lookup({1, 2, 804, 3, 1, 2, 4, 2}), do: "Вищий антикорупційний суд"
  def lookup({1, 2, 804, 3, 1, 2, 4, 3}), do: "Спеціалізований окружний адміністративний суд"
  def lookup({1, 2, 804, 3, 1, 2, 4, 4}), do: "Спеціалізований апеляційний адміністративний суд"
  def lookup({1, 2, 804, 3, 1, 2, 5}), do: "Цільовий профіль судів (Level 3)"
  def lookup({1, 2, 804, 3, 1, 2, 5, 1}), do: "Цільовий профіль безпеки місцевих судів (місцеві загальні, господарські, окружні, адміністративні) судів (Level 4)"
  def lookup({1, 2, 804, 3, 1, 2, 5, 2}), do: "Цільовий профіль безпек апеляційних судів судів (Level 4)"
  def lookup({1, 2, 804, 3, 1, 2, 6}), do: "Цільовий профіль безпеки органів та установи в системі правосуддя (Level 3)"
  def lookup({1, 2, 804, 3, 1, 2, 6, 1}), do: "ДСА (Level 4)"
  def lookup({1, 2, 804, 3, 1, 2, 6, 2}), do: "ТУ ДСА, допоміжні установи (Level 4)"
  def lookup({1, 2, 804, 3, 1, 2, 6, 3}), do: "Рада суддів України - орган суддівського самоврядуванння (Level 4)"
  def lookup({1, 2, 804, 3, 1, 2, 6, 4}), do: "ВРП - орган суддівського врядування (Level 4)"
  def lookup({1, 2, 804, 3, 1, 2, 6, 5}), do: "ВККСУ - орган суддівського врядування (Level 4)"
  def lookup({1, 2, 804, 3, 1, 2, 6, 6}), do: "Національна школа суддів України (Level 4)"
  def lookup({1, 2, 804, 3, 1, 2, 6, 7}), do: "ГРД та ГРМЕ - громадські ради (Level 4)"
  def lookup({1, 2, 804, 3, 1, 2, 6, 8}), do: "Служба судової охорони(Level 4)"
end
