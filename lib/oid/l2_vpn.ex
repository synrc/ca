defmodule CA.L2.VPN do
  @moduledoc """
  Level 2: VPN & PKI Infrastructure Security Profile (Галузевий профіль безпеки для VPN та PKI)

  Цей профіль розширює базовий (L1) додатковими вимогами, які адаптовані для
  продуктів VPN (на базі `tunctl` та L2/L3 тунелів), що працюють у тісній інтеграції
  з повноцінною інфраструктурою PKI та Ідентифікації (CA, OCSP, TSP, LDAP).

  1. VPN & Мережевий доступ (tunctl)
     * `AC-17(1)`, `AC-17(2)`, `AC-17(9)`: Шифрування тунелю, моніторинг підключень, можливість примусового розриву.
     * `SC-7(7)`: Заборона Split Tunneling, маршрутизація всього трафіку через VPN.
     * `SC-10`: Розрив VPN сесії при відсутності активності.
     * `SC-23`: Захист сесій після їх встановлення.

  2. Інфраструктура відкритих ключів (CA, OCSP, TSP, CMP, EST)
     * `IA-5(2)`: Автентифікація на основі відкритого ключа (Mutual TLS для OpenVPN).
     * `SC-17`: Інфраструктура відкритих ключів (випуск і відкликання сертифікатів).
     * `SC-12`: Автоматизація управління ключами через протоколи CMP та EST.
     * `AU-10(5)`: Неспростовність за допомогою цифрових підписів та міток часу TSP (CMS).
     * `IA-7`, `SC-49`, `SC-51`: Строга автентифікація і використання HSM для захисту ключів CA/OCSP/TSP.

  3. Каталог та Ідентифікація (LDAP, EUDI)
     * `IA-2(11)`, `IA-2(12)`: Підтримка MFA, кваліфікованих сертифікатів та EUDI Wallet для доступу.
     * `IA-4`: Управління ідентифікаторами (LDAP).
     * `AC-2`, `AC-3`: Управління обліковими записами та жорсткий контроль доступу.

  4. Криптографічний захист даних (CMS)
     * `SC-8(1)`: Криптографічний захист інформації під час передачі.
     * `SC-28(1)`: Шифрування баз даних каталогів (LDAP) та інформації у стані спокою.
  """

  def controls do
    CA.L1.controls() ++
      [
        # VPN & Remote Access
        CA.SPE.oid(:"id-spe-ac-17-1"),
        CA.SPE.oid(:"id-spe-ac-17-2"),
        CA.SPE.oid(:"id-spe-ac-17-9"),
        CA.SPE.oid(:"id-spe-sc-7-7"),
        CA.SPE.oid(:"id-spe-sc-10"),
        CA.SPE.oid(:"id-spe-sc-23"),

        # PKI (CA, OCSP, TSP)
        CA.SPE.oid(:"id-spe-ia-5-2"),
        CA.SPE.oid(:"id-spe-sc-17"),
        CA.SPE.oid(:"id-spe-sc-12"),
        CA.SPE.oid(:"id-spe-au-10-5"),
        CA.SPE.oid(:"id-spe-ia-7"),
        CA.SPE.oid(:"id-spe-sc-49"),
        CA.SPE.oid(:"id-spe-sc-51"),

        # LDAP & EUDI
        CA.SPE.oid(:"id-spe-ia-4"),
        CA.SPE.oid(:"id-spe-ac-2"),
        CA.SPE.oid(:"id-spe-ac-3"),
        CA.SPE.oid(:"id-spe-ia-2-11"),
        CA.SPE.oid(:"id-spe-ia-2-12"),

        # Cryptography (CMS, At Rest, In Transit)
        CA.SPE.oid(:"id-spe-sc-8-1"),
        CA.SPE.oid(:"id-spe-sc-28-1")
      ]
  end
end
